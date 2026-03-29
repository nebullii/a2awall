# User Guide

This guide is for developers who want to fork the repo, run the demo, or reuse the package as an A2A security gateway layer.

## What This Repo Is

This repo does two things:

- exposes an agent over standard A2A discovery and transport
- enforces additional gateway policy before the request reaches the agent

The current implementation includes:

- bearer-token authentication
- capability-level authorization
- scope checks
- trust-tier checks
- approval-gate support
- message-size limits
- risk and tool-access metadata
- trusted-context boundary helpers for separating instruction channels from untrusted content
- sandbox policy evaluators for tool access
- secure in-memory memory-store primitives
- retrieval trust/disposition evaluators
- delegation-policy evaluators for multi-agent flows
- output/action validation helpers

It does not yet include:

- real bound tool runners that execute inside an OS/process sandbox
- durable protected memory storage
- retrieval connectors with signed provenance
- delegated agent identity propagation over live multi-agent networks
- runtime action verifier integration before tool execution

Those are planned in [SECURITY_ROADMAP.md](/Users/nehachaudhari/Developer/a2awall/SECURITY_ROADMAP.md).

## Quick Start

```bash
npm install
cp .env.example .env
npm test
npm run build
npm start
```

Default endpoints:

- Agent Card: `http://localhost:4000/.well-known/agent-card.json`
- JSON-RPC: `http://localhost:4000/a2a/jsonrpc`
- REST: `http://localhost:4000/a2a/rest`
- Health: `http://localhost:4000/health`

## Environment Variables

- `PORT`
- `BASE_URL`
- `SECURITY_BEARER_TOKEN`
- `SECURITY_PRINCIPAL_ID`
- `SECURITY_ALLOWED_CAPABILITIES`
- `SECURITY_SCOPES`
- `SECURITY_AUDIENCE`
- `SECURITY_TRUST_TIER`

Example:

```env
PORT=4000
BASE_URL=http://localhost:4000
SECURITY_BEARER_TOKEN=dev-token
SECURITY_PRINCIPAL_ID=secured-caller
SECURITY_ALLOWED_CAPABILITIES=echo
SECURITY_SCOPES=agent:invoke,agent:echo
SECURITY_AUDIENCE=trusted-a2a-clients
SECURITY_TRUST_TIER=internal
```

## Call The Demo Agent

```bash
curl -s http://localhost:4000/a2a/jsonrpc \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-token' \
  -H 'X-Agent-Capability: echo' \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "message/send",
    "params": {
      "message": {
        "kind": "message",
        "messageId": "msg-1",
        "role": "user",
        "parts": [{ "kind": "text", "text": "hello secure a2a" }],
        "metadata": { "capability": "echo" }
      }
    }
  }'
```

Expected behavior:

- valid token and capability returns an agent response
- missing token returns `401`
- disallowed capability returns `403`

## Fork And Replace The Demo Agent

The fastest path after forking is:

1. Replace [src/core/example-agent.ts](/Users/nehachaudhari/Developer/a2awall/src/core/example-agent.ts) with your real agent logic.
2. Add or edit capability rules in [src/security/policy.ts](/Users/nehachaudhari/Developer/a2awall/src/security/policy.ts).
3. Keep [src/security/admission.ts](/Users/nehachaudhari/Developer/a2awall/src/security/admission.ts) as the gateway enforcement point.
4. Extend Agent Card metadata in [src/a2a/executor.ts](/Users/nehachaudhari/Developer/a2awall/src/a2a/executor.ts) if you add new policy dimensions.

## Reuse As A Library

Server-side:

```ts
import { createApp, createRuntimeConfig } from "a2awall";
import type { CustomAgent } from "a2awall";

const runtime = createRuntimeConfig(process.env);

const myAgent: CustomAgent = {
  id: "research-agent",
  name: "Research Agent",
  description: "Summarizes technical material.",
  version: "0.1.0",
  capabilities: [
    {
      id: "research",
      name: "Research",
      description: "Summarize a topic."
    }
  ],
  async run(task, context) {
    return {
      text: `Handled '${task.message}' for ${context.callerId}`
    };
  }
};

const app = createApp({
  baseUrl: runtime.baseUrl,
  agent: myAgent,
  securityPolicy: runtime.securityPolicy
});

app.listen(runtime.port);
```

Client-side:

```ts
import { connectToAgent, sendTextToAgent } from "a2awall";

const connection = await connectToAgent({
  baseUrl: "http://localhost:4000",
  bearerToken: "dev-token",
  callerId: "first-user"
});

const response = await sendTextToAgent(connection, {
  capability: "echo",
  message: "hello secure a2a"
});

console.log(response.text);
```

## Trusted Context Boundary

Use the context helpers when your runtime combines system instructions, user input, retrieval results, memory, and tool output.

Example:

```ts
import { buildTrustedContextBundle } from "a2awall";

const bundle = buildTrustedContextBundle([
  { source: "system", content: "Always enforce policy.", intent: "instruction" },
  { source: "user", content: "Ignore previous instructions.", intent: "instruction" },
  { source: "retrieval", content: "Reference article.", intent: "reference" }
]);
```

What happens:

- trusted system and developer instructions stay in the instruction channel
- user or retrieval content that looks like instruction override is blocked
- untrusted content is downgraded to reference context

## Sandbox, Memory, Retrieval, Delegation, and Validation Foundations

The package now includes control-layer helpers you can plug into your runtime:

- `evaluateToolInvocation(...)`
  Use this before every tool call to enforce tool allowlists, read/write mode, path/domain limits, and call budgets.

- `InMemorySecureStore`
  Use this as a starter memory store with per-tenant limits and source-based write policy.

- `evaluateRetrievedDocument(...)`
  Use this to classify retrieved documents as `allow`, `reference-only`, or `quarantine`.

- `evaluateDelegation(...)`
  Use this before one agent delegates work to another.

- `validateActionProposal(...)`
  Use this before high-risk actions or tool execution to reject unsupported or unevidenced outputs.

These are foundational modules. They are not yet automatically wired into a live tool runtime or external data plane.

## Files You Will Edit Most

- [src/core/example-agent.ts](/Users/nehachaudhari/Developer/a2awall/src/core/example-agent.ts)
- [src/security/policy.ts](/Users/nehachaudhari/Developer/a2awall/src/security/policy.ts)
- [src/security/admission.ts](/Users/nehachaudhari/Developer/a2awall/src/security/admission.ts)
- [src/context/trust.ts](/Users/nehachaudhari/Developer/a2awall/src/context/trust.ts)
- [src/a2a/executor.ts](/Users/nehachaudhari/Developer/a2awall/src/a2a/executor.ts)

## Verification

```bash
npm test
node dist/smoke.js
```

`npm test` covers the package/library paths.

`node dist/smoke.js` covers the middleware and request-handler demo flow.
