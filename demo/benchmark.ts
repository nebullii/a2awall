#!/usr/bin/env npx tsx
/**
 * A2AWall × NEST Latency & Throughput Benchmark
 *
 * Measures:
 *   1. Direct-to-NEST baseline (no gateway)
 *   2. Through-A2AWall latency (with full security stack)
 *   3. Delta = pure overhead of A2AWall security layer
 *   4. Concurrent throughput at varying concurrency levels
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createApp } from "../src/app.js";
import { createNestGatewayAgent, type NestAgentEntry } from "./nest-gateway-agent.js";
import type { SecurityPolicy } from "../src/security/policy.js";
import type { Server } from "node:http";

const AGENT_COUNT = parseInt(process.argv[2] ?? "5", 10);
const WARMUP = 50;
const SAMPLES = 500;
const CONCURRENCY_LEVELS = [1, 10, 50, 100];
const GATEWAY_PORT = 4000;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;

// ---------------------------------------------------------------------------
// Stats helpers
// ---------------------------------------------------------------------------

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx]!;
}

function stats(samples: number[]) {
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = samples.reduce((a, b) => a + b, 0);
  return {
    n: samples.length,
    min: sorted[0]!,
    max: sorted[sorted.length - 1]!,
    mean: sum / samples.length,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

function fmtMs(n: number) { return `${n.toFixed(2)}ms`.padStart(9); }
function fmtRps(n: number) { return `${n.toFixed(1)} req/s`.padStart(12); }

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function buildA2APayload(message: string, capability?: string) {
  return {
    jsonrpc: "2.0",
    id: crypto.randomUUID(),
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: crypto.randomUUID(),
        role: "user",
        parts: [{ kind: "text", text: message }],
        metadata: capability ? { capability } : undefined,
      },
    },
  };
}

async function callDirect(nestUrl: string): Promise<number> {
  const start = performance.now();
  const res = await fetch(`${nestUrl}/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(buildA2APayload("benchmark ping", "research")),
  });
  await res.json();
  return performance.now() - start;
}

async function callGateway(capability: string): Promise<number> {
  const start = performance.now();
  const res = await fetch(`${GATEWAY_URL}/a2a/jsonrpc`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer nest-demo-token",
      "X-Agent-Capability": capability,
      "X-Caller-Id": "bench",
    },
    body: JSON.stringify(buildA2APayload("benchmark ping", capability)),
  });
  await res.json();
  return performance.now() - start;
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

async function benchSequential(
  label: string,
  fn: () => Promise<number>,
  samples: number
): Promise<ReturnType<typeof stats>> {
  // Warmup
  for (let i = 0; i < WARMUP; i++) await fn();

  const durations: number[] = [];
  const wallStart = performance.now();
  for (let i = 0; i < samples; i++) {
    durations.push(await fn());
  }
  const wallMs = performance.now() - wallStart;
  const s = stats(durations);
  const rps = (samples / wallMs) * 1000;

  console.log(
    `  ${label.padEnd(32)} ` +
    `p50=${fmtMs(s.p50)}  p95=${fmtMs(s.p95)}  p99=${fmtMs(s.p99)}  ` +
    `mean=${fmtMs(s.mean)}  ${fmtRps(rps)}`
  );
  return s;
}

async function benchConcurrent(
  label: string,
  fn: () => Promise<number>,
  concurrency: number,
  totalSamples: number
): Promise<{ rps: number; s: ReturnType<typeof stats> }> {
  // Warmup
  await Promise.all(Array.from({ length: Math.min(concurrency, 20) }, () => fn()));

  const durations: number[] = [];
  const wallStart = performance.now();

  let completed = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (completed < totalSamples) {
      completed++;
      durations.push(await fn());
    }
  });
  await Promise.all(workers);

  const wallMs = performance.now() - wallStart;
  const s = stats(durations);
  const rps = (durations.length / wallMs) * 1000;

  console.log(
    `  concurrency=${String(concurrency).padStart(3)}  ` +
    `p50=${fmtMs(s.p50)}  p95=${fmtMs(s.p95)}  p99=${fmtMs(s.p99)}  ` +
    `mean=${fmtMs(s.mean)}  ${fmtRps(rps)}`
  );
  return { rps, s };
}

// ---------------------------------------------------------------------------
// NEST startup (same as run-nest-test.ts)
// ---------------------------------------------------------------------------

async function startNestAgents(count: number): Promise<{ process: ChildProcess; agents: NestAgentEntry[] }> {
  return new Promise((resolve, reject) => {
    const py = spawn("python3", ["demo/nest_agents.py", String(count)], {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    });

    let output = "";
    let resolved = false;

    py.stdout!.on("data", (data: Buffer) => {
      const text = data.toString();
      output += text;
      if (!resolved && text.includes("NEST_MANIFEST=")) {
        const match = output.match(/NEST_MANIFEST=(\[.*\])/);
        if (match) {
          const agents = JSON.parse(match[1]) as NestAgentEntry[];
          resolved = true;
          setTimeout(() => resolve({ process: py, agents }), 2000);
        }
      }
    });
    py.stderr!.on("data", () => { /* suppress */ });
    py.on("exit", (code) => { if (!resolved) reject(new Error(`NEST exit ${code}`)); });
    setTimeout(() => { if (!resolved) reject(new Error("NEST startup timeout")); }, 15000);
  });
}

function buildPolicy(agents: NestAgentEntry[]): SecurityPolicy {
  const allCaps = agents.flatMap((a) => a.capabilities);
  const capPolicies: SecurityPolicy["capabilityPolicies"] = {};
  for (const a of agents) {
    for (const cap of a.capabilities) {
      capPolicies[cap] = {
        name: cap, description: cap, tags: [cap],
        requiredScopes: [`agent:${cap}`],
        requiredTrustTier: "public",
        riskLevel: "low",
        approvalRequired: false,
        toolAccess: "none", allowedToolIds: [],
        maxToolCalls: 0, maxRuntimeMs: 5000, maxMessageCharacters: 8000,
      };
    }
  }
  return {
    securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
    securityRequirements: [{ bearerAuth: [] }],
    identities: [{
      token: "nest-demo-token",
      principalId: "bench",
      scopes: ["agent:invoke", ...allCaps.map((c) => `agent:${c}`)],
      trustTier: "internal",
      allowedCapabilities: allCaps,
    }],
    capabilityPolicies: capPolicies,
    metadata: {
      audience: "bench", trustTier: "internal",
      capabilityHeader: "x-agent-capability",
      capabilityMetadataKey: "capability",
      requestIdHeader: "x-request-id",
      approvalHeader: "x-approval-token",
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`\n═══ A2AWall × NEST Benchmark (${AGENT_COUNT} agents) ═══\n`);
  console.log(`Warmup: ${WARMUP} req · Samples: ${SAMPLES} req\n`);

  console.log("Starting NEST agents + A2AWall gateway...");
  const { process: nestProc, agents } = await startNestAgents(AGENT_COUNT);

  const app = createApp({
    baseUrl: GATEWAY_URL,
    agent: createNestGatewayAgent(agents),
    securityPolicy: buildPolicy(agents),
  });
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(GATEWAY_PORT, () => resolve(s));
  });

  // Silence the per-request log from middleware during benchmark
  const origWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    const s = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString();
    if (s.includes('"event":"agent_request"') || s.includes("[A2AWall]")) return true;
    return origWrite(chunk, ...rest as Parameters<typeof origWrite>);
  }) as typeof process.stdout.write;

  await new Promise((r) => setTimeout(r, 1000));

  const nestUrl = agents[0]!.url;

  try {
    // ── Sequential latency ──────────────────────────────────────────────
    console.log("\n── Sequential latency (single client) ──");
    const directStats = await benchSequential(
      "Direct → NEST (baseline)",
      () => callDirect(nestUrl),
      SAMPLES
    );
    const gatewayStats = await benchSequential(
      "Through A2AWall gateway",
      () => callGateway("research"),
      SAMPLES
    );

    const overheadP50 = gatewayStats.p50 - directStats.p50;
    const overheadMean = gatewayStats.mean - directStats.mean;
    const overheadPct = (overheadMean / directStats.mean) * 100;

    console.log(`\n  A2AWall overhead:  p50 +${overheadP50.toFixed(2)}ms  ` +
      `mean +${overheadMean.toFixed(2)}ms  (+${overheadPct.toFixed(1)}%)`);

    // ── Concurrent throughput ───────────────────────────────────────────
    console.log("\n── Concurrent throughput — Direct to NEST ──");
    const directRps: number[] = [];
    for (const c of CONCURRENCY_LEVELS) {
      const r = await benchConcurrent(`direct c=${c}`, () => callDirect(nestUrl), c, 500);
      directRps.push(r.rps);
    }

    console.log("\n── Concurrent throughput — Through A2AWall ──");
    const gatewayRps: number[] = [];
    for (const c of CONCURRENCY_LEVELS) {
      const r = await benchConcurrent(`gateway c=${c}`, () => callGateway("research"), c, 500);
      gatewayRps.push(r.rps);
    }

    // ── Summary ─────────────────────────────────────────────────────────
    console.log("\n═══ Summary ═══\n");
    console.log("  Throughput (req/s) by concurrency:");
    console.log("  " + "─".repeat(64));
    console.log(`  ${"concurrency".padEnd(14)}${"direct".padStart(14)}${"gateway".padStart(14)}${"overhead".padStart(14)}`);
    for (let i = 0; i < CONCURRENCY_LEVELS.length; i++) {
      const c = CONCURRENCY_LEVELS[i]!;
      const d = directRps[i]!;
      const g = gatewayRps[i]!;
      const pct = ((d - g) / d * 100);
      console.log(
        `  ${String(c).padEnd(14)}` +
        `${d.toFixed(1).padStart(14)}` +
        `${g.toFixed(1).padStart(14)}` +
        `${("-" + pct.toFixed(1) + "%").padStart(14)}`
      );
    }
    console.log();
  } finally {
    process.stdout.write = origWrite;
    server.close();
    nestProc.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    process.exit(0);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
