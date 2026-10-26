/**
 * A2AWall CustomAgent that proxies requests to downstream NEST agents.
 *
 * Each NEST agent's capabilities are mapped to A2AWall capability policies.
 * The gateway applies security (admission, trust-tier, scopes) before
 * forwarding to the real NEST agent.
 */

import type { CustomAgent, AgentTask, AgentContext, AgentResult, AgentCapability } from "../src/core/agent.js";

export interface NestAgentEntry {
  id: string;
  name: string;
  url: string;
  capabilities: string[];
  port: number;
}

/**
 * Build a capability-to-agent routing map from the NEST manifest.
 */
function buildRoutingTable(agents: NestAgentEntry[]): Map<string, NestAgentEntry> {
  const table = new Map<string, NestAgentEntry>();
  for (const agent of agents) {
    for (const cap of agent.capabilities) {
      table.set(cap, agent);
    }
  }
  return table;
}

/**
 * Send a message to a NEST agent's A2A endpoint and return the response text.
 */
async function callNestAgent(agentUrl: string, message: string, capability: string): Promise<string> {
  const payload = {
    jsonrpc: "2.0",
    id: crypto.randomUUID(),
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: crypto.randomUUID(),
        role: "user",
        parts: [{ kind: "text", text: message }],
        metadata: { capability }
      }
    }
  };

  // NEST's A2AStarletteApplication serves on root "/"
  const response = await fetch(`${agentUrl}/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    return `[Gateway Error] NEST agent at ${agentUrl} returned ${response.status}`;
  }

  const result = await response.json() as Record<string, unknown>;
  return extractText(result);
}

function extractText(result: Record<string, unknown>): string {
  // JSON-RPC response
  if (result.result && typeof result.result === "object") {
    const r = result.result as Record<string, unknown>;
    // Task-style response
    if (r.status && typeof r.status === "object") {
      const status = r.status as Record<string, unknown>;
      if (status.message && typeof status.message === "object") {
        const msg = status.message as { parts?: Array<{ text?: string }> };
        return msg.parts?.map(p => p.text).join("\n") ?? JSON.stringify(result);
      }
    }
    // Message-style response
    if (r.parts && Array.isArray(r.parts)) {
      return (r.parts as Array<{ text?: string }>).map(p => p.text).join("\n");
    }
  }
  return JSON.stringify(result);
}

/**
 * Create the gateway agent that routes to NEST agents.
 */
export function createNestGatewayAgent(nestAgents: NestAgentEntry[]): CustomAgent {
  const routingTable = buildRoutingTable(nestAgents);

  const capabilities: AgentCapability[] = [];
  for (const agent of nestAgents) {
    for (const cap of agent.capabilities) {
      capabilities.push({
        id: cap,
        name: `${cap} (via ${agent.name})`,
        description: `Routed to NEST agent '${agent.id}' at ${agent.url}`,
      });
    }
  }

  return {
    id: "nest-gateway",
    name: "NEST Gateway (A2AWall Secured)",
    description:
      "Security gateway that applies A2AWall admission control, " +
      "trust-tier validation, and capability scoping before routing " +
      "requests to downstream NEST agents.",
    version: "1.0.0",
    capabilities,

    async run(task: AgentTask, context: AgentContext): Promise<AgentResult> {
      const capability = task.capability ?? "unknown";
      const target = routingTable.get(capability);

      if (!target) {
        return {
          text: `[Gateway] No NEST agent registered for capability '${capability}'. ` +
            `Available: ${[...routingTable.keys()].join(", ")}`,
        };
      }

      console.log(
        `  [A2AWall] ${context.callerId} → ${target.id} ` +
        `(capability=${capability}, request=${context.requestId.slice(0, 8)})`
      );

      try {
        const responseText = await callNestAgent(target.url, task.message, capability);
        return {
          text: `[Secured via A2AWall → ${target.id}] ${responseText}`,
        };
      } catch (error) {
        return {
          text: `[Gateway Error] Failed to reach ${target.id} at ${target.url}: ${error}`,
        };
      }
    },
  };
}
