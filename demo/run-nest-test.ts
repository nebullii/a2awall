#!/usr/bin/env npx tsx
/**
 * A2AWall × NEST Integration Test
 *
 * Starts N NEST agents (Python), then an A2AWall gateway in front of them,
 * and runs a test suite demonstrating security enforcement + agent routing.
 *
 * Usage:
 *   npx tsx demo/run-nest-test.ts          # 5 agents (default)
 *   npx tsx demo/run-nest-test.ts 2        # 2 agents
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createApp } from "../src/app.js";
import { createNestGatewayAgent, type NestAgentEntry } from "./nest-gateway-agent.js";
import type { SecurityPolicy } from "../src/security/policy.js";
import type { Server } from "node:http";

const AGENT_COUNT = parseInt(process.argv[2] ?? "5", 10);
const GATEWAY_PORT = 4000;
const GATEWAY_URL = `http://localhost:${GATEWAY_PORT}`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function header(text: string) {
  const line = "═".repeat(60);
  console.log(`\n${line}`);
  console.log(`  ${text}`);
  console.log(`${line}\n`);
}

function ok(text: string) { console.log(`  ✅ ${text}`); }
function fail(text: string) { console.log(`  ❌ ${text}`); }
function info(text: string) { console.log(`  ℹ️  ${text}`); }

// ---------------------------------------------------------------------------
// Start NEST agents (Python subprocess)
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
      process.stdout.write(`  [NEST] ${text}`);

      // Parse manifest line
      if (!resolved && text.includes("NEST_MANIFEST=")) {
        const match = output.match(/NEST_MANIFEST=(\[.*\])/);
        if (match) {
          try {
            const agents = JSON.parse(match[1]) as NestAgentEntry[];
            resolved = true;
            // Give agents a moment to bind ports
            setTimeout(() => resolve({ process: py, agents }), 2000);
          } catch (e) {
            reject(new Error(`Failed to parse NEST manifest: ${e}`));
          }
        }
      }
    });

    py.stderr!.on("data", (data: Buffer) => {
      // Suppress noisy warnings, show errors
      const text = data.toString();
      if (text.includes("Error") || text.includes("error")) {
        process.stderr.write(`  [NEST stderr] ${text}`);
      }
    });

    py.on("error", reject);
    py.on("exit", (code) => {
      if (!resolved) reject(new Error(`NEST agents exited with code ${code}`));
    });

    // Timeout
    setTimeout(() => {
      if (!resolved) reject(new Error("Timed out waiting for NEST agents to start"));
    }, 15000);
  });
}

// ---------------------------------------------------------------------------
// Build security policy for the NEST gateway
// ---------------------------------------------------------------------------

function buildGatewayPolicy(agents: NestAgentEntry[]): SecurityPolicy {
  const allCapabilities = agents.flatMap((a) => a.capabilities);

  const capabilityPolicies: SecurityPolicy["capabilityPolicies"] = {};
  for (const agent of agents) {
    for (const cap of agent.capabilities) {
      const publicCaps = ["research", "summarize"];
      capabilityPolicies[cap] = {
        name: cap,
        description: `Capability '${cap}' routed to NEST agent '${agent.id}'.`,
        tags: [cap, agent.id],
        requiredScopes: [`agent:${cap}`],
        requiredTrustTier: publicCaps.includes(cap) ? "public" : "partner",
        riskLevel: cap === "coordinate" || cap === "delegate" ? "medium" : "low",
        approvalRequired: false,
        toolAccess: "none",
        allowedToolIds: [],
        maxToolCalls: 0,
        maxRuntimeMs: 5000,
        maxMessageCharacters: 8000,
      };
    }
  }

  return {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "opaque-token",
        description: "Bearer token for NEST gateway access.",
      },
    },
    securityRequirements: [{ bearerAuth: [] }],
    identities: [
      {
        token: "nest-demo-token",
        principalId: "demo-caller",
        scopes: ["agent:invoke", ...allCapabilities.map((c) => `agent:${c}`)],
        trustTier: "internal",
        allowedCapabilities: allCapabilities,
      },
      {
        token: "public-token",
        principalId: "public-caller",
        scopes: ["agent:invoke", "agent:research", "agent:summarize"],
        trustTier: "public",
        allowedCapabilities: ["research", "summarize"],
      },
    ],
    capabilityPolicies,
    metadata: {
      audience: "nest-demo",
      trustTier: "internal",
      capabilityHeader: "x-agent-capability",
      capabilityMetadataKey: "capability",
      requestIdHeader: "x-request-id",
      approvalHeader: "x-approval-token",
    },
  };
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

async function sendRequest(
  capability: string,
  message: string,
  token: string,
  callerId: string
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${GATEWAY_URL}/a2a/jsonrpc`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "X-Agent-Capability": capability,
      "X-Caller-Id": callerId,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: crypto.randomUUID(),
      method: "message/send",
      params: {
        message: {
          kind: "message",
          messageId: crypto.randomUUID(),
          role: "user",
          parts: [{ kind: "text", text: message }],
          metadata: { capability },
        },
      },
    }),
  });

  const body = await res.json() as Record<string, unknown>;
  return { status: res.status, body };
}

function getResponseText(body: Record<string, unknown>): string {
  try {
    const result = body.result as Record<string, unknown>;
    if (result?.status && typeof result.status === "object") {
      const status = result.status as Record<string, unknown>;
      if (status.message && typeof status.message === "object") {
        const msg = status.message as { parts?: Array<{ text?: string }> };
        return msg.parts?.map((p) => p.text).join("\n") ?? "";
      }
    }
  } catch {
    // ignore
  }
  return JSON.stringify(body).slice(0, 200);
}

async function runTests(agents: NestAgentEntry[]) {
  let passed = 0;
  let failed = 0;

  function check(label: string, condition: boolean, detail?: string) {
    if (condition) {
      ok(label);
      passed++;
    } else {
      fail(`${label}${detail ? ` — ${detail}` : ""}`);
      failed++;
    }
  }

  // ── Test 1: Health endpoint ──────────────────────────────────────────
  header("Test 1 · Gateway Health Check");
  {
    const res = await fetch(`${GATEWAY_URL}/health`);
    const body = await res.json() as Record<string, unknown>;
    check("Health endpoint returns 200", res.status === 200);
    check("Reports all capabilities", Array.isArray(body.capabilities));
    info(`Capabilities: ${(body.capabilities as string[]).join(", ")}`);
  }

  // ── Test 2: Agent card ───────────────────────────────────────────────
  header("Test 2 · Agent Card Discovery");
  {
    const res = await fetch(`${GATEWAY_URL}/.well-known/agent-card.json`);
    const card = await res.json() as Record<string, unknown>;
    check("Agent card is accessible", res.status === 200);
    check(
      "Card lists all NEST agent skills",
      Array.isArray(card.skills) && (card.skills as unknown[]).length === agents.flatMap(a => a.capabilities).length
    );
    info(`Agent: ${card.name}`);
  }

  // ── Test 3: Auth enforcement ─────────────────────────────────────────
  header("Test 3 · Security — Missing Token (401)");
  {
    const res = await fetch(`${GATEWAY_URL}/a2a/jsonrpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Agent-Capability": "research" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: "1", method: "message/send",
        params: { message: { kind: "message", messageId: "m1", role: "user", parts: [{ kind: "text", text: "test" }] } },
      }),
    });
    check("Missing bearer token → 401", res.status === 401);
  }

  // ── Test 4: Invalid capability ───────────────────────────────────────
  header("Test 4 · Security — Invalid Capability (403)");
  {
    const res = await fetch(`${GATEWAY_URL}/a2a/jsonrpc`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer nest-demo-token",
        "X-Agent-Capability": "hack-the-planet",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: "2", method: "message/send",
        params: { message: { kind: "message", messageId: "m2", role: "user", parts: [{ kind: "text", text: "test" }] } },
      }),
    });
    check("Unknown capability → 403", res.status === 403);
  }

  // ── Test 5: Trust tier enforcement ──────────────────────────────────
  header("Test 5 · Security — Trust Tier Enforcement");
  {
    // public-token can access research (allowed) but not coordinate (needs partner+)
    const res1 = await sendRequest("research", "test query", "public-token", "public-caller");
    check("Public caller → research capability: allowed", res1.status === 200);

    const res2 = await fetch(`${GATEWAY_URL}/a2a/jsonrpc`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer public-token",
        "X-Agent-Capability": "coordinate",
        "X-Caller-Id": "public-caller",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: "3", method: "message/send",
        params: { message: { kind: "message", messageId: "m3", role: "user", parts: [{ kind: "text", text: "test" }] } },
      }),
    });
    check("Public caller → coordinate capability: denied (403)", res2.status === 403);
  }

  // ── Test 6: Route to each NEST agent ────────────────────────────────
  header("Test 6 · Routing — Message Each NEST Agent");
  for (const agent of agents) {
    const cap = agent.capabilities[0]!;
    const { status, body } = await sendRequest(cap, `Hello from the gateway test`, "nest-demo-token", "test-runner");
    const text = getResponseText(body);
    check(
      `${agent.name} (${cap}): routed successfully`,
      status === 200 && text.length > 0,
      text.slice(0, 100)
    );
    info(`Response: ${text.slice(0, 120)}`);
  }

  // ── Test 7: Cross-agent workflow simulation ─────────────────────────
  if (AGENT_COUNT >= 4) {
    header("Test 7 · Workflow — Multi-Agent Pipeline");
    info("Simulating: coordinator → researcher → analyst → writer → reviewer");

    const steps = [
      { cap: "coordinate", msg: "Plan analysis of A2A security patterns" },
      { cap: "research", msg: "Gather data on A2A security patterns" },
      { cap: "analyze", msg: "Analyze the gathered research data" },
      { cap: "write", msg: "Draft a report on the analysis findings" },
      { cap: "review", msg: "Review the drafted report for accuracy" },
    ];

    for (const step of steps.slice(0, agents.flatMap(a => a.capabilities).length)) {
      const { status, body } = await sendRequest(step.cap, step.msg, "nest-demo-token", "pipeline-runner");
      const text = getResponseText(body);
      check(`Pipeline step '${step.cap}': completed`, status === 200);
      info(`  ${text.slice(0, 100)}`);
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────
  header("Results");
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  console.log(`  Total:  ${passed + failed}\n`);

  return failed === 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  header(`A2AWall × NEST Integration Test (${AGENT_COUNT} agents)`);

  // 1. Start NEST agents
  info("Starting NEST agents...");
  let nestProcess: ChildProcess | undefined;
  let server: Server | undefined;

  try {
    const { process: np, agents } = await startNestAgents(AGENT_COUNT);
    nestProcess = np;

    console.log();
    info(`${agents.length} NEST agents running:`);
    for (const a of agents) {
      info(`  ${a.id} → ${a.url} [${a.capabilities.join(", ")}]`);
    }

    // 2. Start A2AWall gateway
    info("\nStarting A2AWall security gateway...");
    const policy = buildGatewayPolicy(agents);
    const gatewayAgent = createNestGatewayAgent(agents);
    const app = createApp({
      baseUrl: GATEWAY_URL,
      agent: gatewayAgent,
      securityPolicy: policy,
    });

    server = await new Promise<Server>((resolve) => {
      const s = app.listen(GATEWAY_PORT, () => {
        ok(`A2AWall gateway running on ${GATEWAY_URL}`);
        info(`Agent card: ${GATEWAY_URL}/.well-known/agent-card.json`);
        resolve(s);
      });
    });

    // 3. Give everything a moment to stabilize
    await sleep(1000);

    // 4. Run tests
    const allPassed = await runTests(agents);

    // 5. Cleanup
    header("Cleanup");
    server.close();
    nestProcess.kill("SIGTERM");
    info("All processes stopped.");

    process.exit(allPassed ? 0 : 1);
  } catch (error) {
    fail(`Fatal error: ${error}`);
    server?.close();
    nestProcess?.kill("SIGTERM");
    process.exit(1);
  }
}

main();
