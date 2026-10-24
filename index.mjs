// dsh-traffic-guard — expose the local `netguard` byte-budget gate as agent tools.
//
// Why: when an agent's downloads go through a metered proxy (a paid "airport"
// plan, a mobile hotspot, a corporate egress gateway), a single careless
// `curl -O` can burn gigabytes. The proxy client's own counter tells you the
// total, not which call caused it, and desktop app auto-updates may silently
// consume plan bytes too.
//
// This plugin is a thin wrapper. The policy itself — direct-first routing,
// stall detection, per-call/per-day budget, redirect re-evaluation, ledger —
// lives in `cli/netguard.py`, which runs standalone and is testable without dsh.
//
// No harness imports: the bundle is installed as a linked package, so node
// resolution cannot see dsh's own node_modules. Only node builtins are used.

import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'traffic-guard'
export const inject = ['tools']

const PACKAGE_ROOT = path.dirname(fileURLToPath(import.meta.url))
const HOME = os.homedir()

function resolveCli(config) {
  const candidates = [
    config?.cliPath,
    process.env.NETGUARD_CLI,
    path.join(PACKAGE_ROOT, 'cli', 'netguard.py'),
    path.join(HOME, '.dsh', 'netguard', 'netguard.py'),
  ].filter((candidate) => typeof candidate === 'string' && candidate.length > 0)
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }
  return candidates[0] ?? path.join(PACKAGE_ROOT, 'cli', 'netguard.py')
}

function pythonCandidates(config) {
  const configured = config?.pythonPath || process.env.NETGUARD_PYTHON
  const platformDefaults = process.platform === 'win32'
    ? ['python', 'py', 'python3']
    : process.platform === 'darwin'
      ? ['/usr/bin/python3', 'python3', 'python']
      : ['python3', '/usr/bin/python3', 'python']
  return [...new Set([configured, ...platformDefaults].filter(Boolean))]
}

function execOnce(python, cli, args, env, timeoutMs) {
  return new Promise((resolve, reject) => {
    execFile(python, [cli, ...args], { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env },
      (error, stdout, stderr) => {
        const out = String(stdout ?? '').trim()
        const err = String(stderr ?? '').trim()
        if (error && !out) {
          const wrapped = new Error(err || error.message)
          wrapped.code = error.code
          reject(wrapped)
          return
        }
        resolve({ code: error ? (error.code ?? 1) : 0, stdout: out, stderr: err })
      })
  })
}

async function runCli(config, args, timeoutMs = 900000) {
  const cli = resolveCli(config)
  const env = { ...process.env }
  if (config?.home) env.NETGUARD_HOME = config.home
  let lastError
  for (const python of pythonCandidates(config)) {
    try {
      return await execOnce(python, cli, args, env, timeoutMs)
    } catch (error) {
      // Only a missing interpreter is worth retrying with the next candidate;
      // a non-zero exit is a real result (budget refusal, network failure).
      if (error.code !== 'ENOENT') throw error
      lastError = error
    }
  }
  throw lastError
}

function textValue(text) {
  return { text }
}

const textOutput = {
  schema: {
    type: 'object',
    properties: { text: { type: 'string' } },
    required: ['text'],
    additionalProperties: false,
  },
  render: (_args, value) => [{ type: 'text', text: String(value?.text ?? '') }],
}

function usageTool(config) {
  return {
    name: 'net_usage',
    description:
      'Read the local netguard traffic ledger: how many bytes today / over the last N days went ' +
      'through the metered proxy, split by host and route (direct vs proxy). This is the only ' +
      'per-host accounting available, because proxy clients typically report only a plan-level total.',
    parameters: {
      type: 'object',
      properties: {
        days: { type: 'integer', minimum: 1, maximum: 90, default: 7, description: 'How many days back to summarise.' },
      },
      additionalProperties: false,
    },
    output: textOutput,
    async execute(args) {
      const res = await runCli(config, ['report', '--json', '--days', String(Number(args?.days ?? 7))])
      return textValue(res.stdout || '{"by_day":{},"by_host":{}}')
    },
    isConcurrencySafe: () => true,
  }
}

function probeTool(config) {
  return {
    name: 'net_probe',
    description:
      'Check whether a URL is reachable DIRECTLY before downloading it. Returns the routing class ' +
      'and a recommendation (direct / proxy / none). Use this before a large download: direct traffic ' +
      'does not spend metered-proxy budget, so a "direct_ok" result means no proxy is needed.',
    parameters: {
      type: 'object',
      properties: { url: { type: 'string', description: 'URL to probe (HEAD request, a few hundred bytes at most).' } },
      required: ['url'],
      additionalProperties: false,
    },
    output: textOutput,
    timeoutMs: 60000,
    async execute(args) {
      const res = await runCli(config, ['probe', String(args?.url ?? ''), '--json'], 60000)
      return textValue(res.stdout)
    },
    isConcurrencySafe: () => true,
  }
}

function downloadTool(config) {
  return {
    name: 'net_download',
    description:
      'Download a file through the netguard policy: direct first; escalate to the local proxy ONLY ' +
      'when the host is allowlisted and the direct attempt stalls; every proxy byte is charged against ' +
      'a per-call (default 128MiB) and per-day (default 300MiB) budget and refused when exhausted. ' +
      'Redirects are re-evaluated hop by hop. Returns a JSON summary ' +
      '(route/bytes/seconds/output/hops/error). Budget or size refusals are hard failures, not warnings.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'URL to download.' },
        output: { type: 'string', description: 'Destination path (defaults to the URL basename).' },
        max_bytes: { type: 'integer', minimum: 1, description: 'Hard cap for this call in bytes.' },
        force: { type: 'boolean', description: 'Ignore the per-day budget for this call.' },
        no_escalate: { type: 'boolean', description: 'Never fall back to the proxy.' },
      },
      required: ['url'],
      additionalProperties: false,
    },
    output: textOutput,
    timeoutMs: 900000,
    async execute(args) {
      const argv = ['dl', String(args?.url ?? '')]
      if (args?.output) argv.push('-o', String(args.output))
      if (args?.max_bytes) argv.push('--max-bytes', String(args.max_bytes))
      if (args?.force === true) argv.push('--force')
      if (args?.no_escalate === true) argv.push('--no-escalate')
      argv.push('--json')
      const res = await runCli(config, argv)
      let payload
      try {
        payload = JSON.parse(res.stdout)
      } catch {
        payload = { code: res.code, raw: res.stdout }
      }
      if (payload.ok === false || res.code !== 0) {
        throw new Error(JSON.stringify(payload))
      }
      return textValue(JSON.stringify(payload))
    },
    isConcurrencySafe: () => false,
  }
}

export function apply(ctx, config = {}) {
  const tools = ctx.get('tools')
  if (tools === undefined) return
  ctx.effect(() => {
    const disposers = [
      tools.register(usageTool(config)),
      tools.register(probeTool(config)),
      tools.register(downloadTool(config)),
    ]
    return () => {
      for (const dispose of disposers) {
        try {
          dispose()
        } catch {
          /* already disposed */
        }
      }
    }
  })
}
