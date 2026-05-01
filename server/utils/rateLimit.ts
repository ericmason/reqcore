import type { H3Event } from 'h3'
import { BlockList, isIP } from 'node:net'

// ─────────────────────────────────────────────
// In-memory sliding window rate limiter
// ─────────────────────────────────────────────

/**
 * Configuration for a rate limiter instance.
 *
 * @param windowMs - Time window in milliseconds
 * @param maxRequests - Maximum number of requests allowed within the window
 * @param message - Error message returned when the limit is exceeded
 */
interface RateLimitConfig {
  windowMs: number
  maxRequests: number
  message?: string
}

interface RateLimitEntry {
  timestamps: number[]
}

/**
 * Create a reusable rate limiter scoped by client IP.
 *
 * Uses a sliding window algorithm — each request records a timestamp,
 * and only timestamps within the current window are counted.
 *
 * WARNING: This is an in-memory implementation that resets on restart and
 * does not share state across instances. For production at scale, replace
 * with a Redis-backed implementation (e.g. `@upstash/ratelimit`) to
 * handle multi-instance deployments.
 *
 * @example
 * ```ts
 * const limiter = createRateLimiter({ windowMs: 60_000, maxRequests: 5 })
 *
 * export default defineEventHandler(async (event) => {
 *   await limiter(event)
 *   // ... handler logic
 * })
 * ```
 */
export function createRateLimiter(config: RateLimitConfig) {
  const { windowMs, maxRequests, message = 'Too many requests, please try again later' } = config
  const store = new Map<string, RateLimitEntry>()

  if (process.env.NODE_ENV === 'production') {
    console.warn(
      '[Reqcore] In-memory rate limiter active. State resets on restart and is not shared across instances. ' +
      'For horizontal scaling, replace with a Redis-backed implementation (e.g. @upstash/ratelimit).',
    )
  }

  // Periodically prune stale entries to prevent unbounded memory growth
  const PRUNE_INTERVAL = Math.max(windowMs * 2, 60_000)
  setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of store) {
      // Remove entries with no timestamps within the window
      entry.timestamps = entry.timestamps.filter((t) => now - t < windowMs)
      if (entry.timestamps.length === 0) {
        store.delete(key)
      }
    }
  }, PRUNE_INTERVAL).unref() // .unref() prevents the timer from keeping the process alive

  /**
   * Check and enforce the rate limit for the current request.
   * Throws a 429 error if the limit is exceeded.
   * Sets standard rate limit headers on every response.
   */
  return async function rateLimit(event: H3Event): Promise<void> {
    const ip = getClientIp(event)
    const now = Date.now()

    let entry = store.get(ip)
    if (!entry) {
      entry = { timestamps: [] }
      store.set(ip, entry)
    }

    // Remove timestamps outside the current window
    entry.timestamps = entry.timestamps.filter((t) => now - t < windowMs)

    // Set rate limit headers (draft RFC 7.2 / common convention)
    const remaining = Math.max(0, maxRequests - entry.timestamps.length)
    const resetSeconds = entry.timestamps.length > 0
      ? Math.ceil((entry.timestamps[0]! + windowMs - now) / 1000)
      : Math.ceil(windowMs / 1000)

    setResponseHeaders(event, {
      'X-RateLimit-Limit': String(maxRequests),
      'X-RateLimit-Remaining': String(remaining),
      'X-RateLimit-Reset': String(resetSeconds),
    })

    if (entry.timestamps.length >= maxRequests) {
      setResponseHeader(event, 'Retry-After', resetSeconds)
      throw createError({
        statusCode: 429,
        statusMessage: message,
      })
    }

    // Record this request
    entry.timestamps.push(now)
  }
}

/**
 * Extract the client IP from the request.
 *
 * Security: Does NOT trust proxy headers (X-Forwarded-For, X-Real-IP) by default
 * because they are trivially spoofable by direct clients. Uses the socket remote
 * address unless the request came from a trusted proxy.
 *
 * Three trust models, checked in order:
 *
 * 1. CloudFront — when `CloudFront-Viewer-Address` is present and the socket
 *    peer is in TRUSTED_PROXY_CIDRS, use that header. CloudFront sets it
 *    itself; it is not viewer-supplied, so it cannot be spoofed.
 *    (Requires the cache behavior's origin request policy to forward
 *    `CloudFront-Viewer-Address` — e.g. AWS-managed `AllViewerAndCloudFrontHeaders`.)
 *
 * 2. Multi-hop CIDR — when TRUSTED_PROXY_CIDRS is set, pop trusted hops off
 *    the right of X-Forwarded-For until reaching the first untrusted entry.
 *    That entry is the real client. Handles chains like
 *    Client → CDN → ALB → pod where intermediate hops are in known CIDRs.
 *
 * 3. Legacy single-hop — when TRUSTED_PROXY_IP is set and matches the socket
 *    peer exactly, take the leftmost X-Forwarded-For entry. Original
 *    Reqcore behavior, kept for Railway/Cloudflare single-proxy setups.
 *
 * 4. Default — return the socket remote address.
 */
const _trustedBlockList: BlockList | null = (() => {
  const cidrs = env.TRUSTED_PROXY_CIDRS
  if (!cidrs || cidrs.length === 0) return null
  const list = new BlockList()
  for (const cidr of cidrs) {
    const slash = cidr.indexOf('/')
    if (slash === -1) {
      // No prefix → treat as a single host
      const family = isIP(cidr)
      if (family === 4 || family === 6) {
        list.addAddress(cidr, family === 4 ? 'ipv4' : 'ipv6')
      }
      continue
    }
    const addr = cidr.slice(0, slash)
    const prefix = Number(cidr.slice(slash + 1))
    const family = isIP(addr)
    if ((family === 4 || family === 6) && Number.isInteger(prefix)) {
      try {
        list.addSubnet(addr, prefix, family === 4 ? 'ipv4' : 'ipv6')
      } catch {
        // Skip malformed entry; rely on env validation messaging instead.
      }
    }
  }
  return list
})()

function isTrustedHop(ip: string): boolean {
  if (!_trustedBlockList) return false
  const family = isIP(ip)
  if (family === 0) return false
  return _trustedBlockList.check(ip, family === 4 ? 'ipv4' : 'ipv6')
}

function getClientIp(event: H3Event): string {
  const socketIp = getRequestIP(event) ?? ''

  // 1. CloudFront-Viewer-Address (signed by CloudFront, format "<ip>:<port>").
  if (socketIp && isTrustedHop(socketIp)) {
    const cfViewer = getHeader(event, 'cloudfront-viewer-address')
    if (cfViewer) {
      // IPv4 form: "1.2.3.4:443"; IPv6 form: "2001:db8::1:443" (last colon).
      const lastColon = cfViewer.lastIndexOf(':')
      const ip = lastColon > 0 ? cfViewer.slice(0, lastColon) : cfViewer
      if (isIP(ip)) return ip
    }
  }

  // 2. Multi-hop XFF with CIDR-based trust.
  if (_trustedBlockList && socketIp && isTrustedHop(socketIp)) {
    const forwarded = getHeader(event, 'x-forwarded-for')
    if (forwarded) {
      const hops = forwarded.split(',').map((s) => s.trim()).filter(Boolean)
      // Walk right-to-left, popping trusted hops; first untrusted is the client.
      for (let i = hops.length - 1; i >= 0; i--) {
        const hop = hops[i]!
        if (!isTrustedHop(hop)) return hop
      }
      // All hops were trusted — fall through to socket peer.
    }
  }

  // 3. Legacy single-hop TRUSTED_PROXY_IP behavior.
  const trustedProxy = env.TRUSTED_PROXY_IP
  if (trustedProxy && socketIp === trustedProxy) {
    const forwarded = getHeader(event, 'x-forwarded-for')
    if (forwarded) {
      const firstIp = forwarded.split(',')[0]?.trim()
      if (firstIp) return firstIp
    }
    const realIp = getHeader(event, 'x-real-ip')
    if (realIp) return realIp
  }

  // 4. Default: socket remote address (cannot be spoofed).
  return socketIp || '0.0.0.0'
}
