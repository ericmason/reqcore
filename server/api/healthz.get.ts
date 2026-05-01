/**
 * Liveness/readiness probe.
 *
 * Returns 200 once the Nitro process is accepting requests. Intentionally
 * does NOT touch the database or S3 — those are dependency health, not pod
 * health. A pod with a flapping DB connection should keep serving cached
 * pages and reporting healthy so it isn't restart-looped; deep checks
 * belong on a separate authenticated endpoint (see /api/updates/system).
 *
 * Unauthenticated by design — k8s/ALB probes can't carry credentials.
 */
export default defineEventHandler(() => ({
  ok: true,
  service: 'reqcore',
  ts: new Date().toISOString(),
}))
