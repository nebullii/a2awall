# A2AWall

[![CI](https://github.com/nebullii/a2awall/actions/workflows/ci.yml/badge.svg)](https://github.com/nebullii/a2awall/actions/workflows/ci.yml)

Reusable TypeScript package for exposing agents over standard A2A while enforcing a stronger gateway security layer.

What is implemented now:

- A2A-compatible Agent Card and transports
- gateway admission control
- bearer-token auth
- scope and capability checks
- trust-tier checks
- approval-gate support
- message-size limits
- risk and tool-access metadata
- trusted-context boundary helpers

What is not fully implemented yet:

- process or container isolation for tool execution. The runtime enforces an
  allowlist, an operation matrix, a call budget and a wall-clock deadline, but it
  does not isolate the tool process
- credential verification beyond opaque bearer tokens. `IdentityResolver` is the
  seam for a signed-token verifier; no JWT or OIDC verifier ships in the box
- Agent Card signing. The card carries a `signatures` slot, but A2AWall does not
  produce JWS signatures
- memory security backend
- retrieval provenance enforcement
- multi-agent delegation control plane

Use this repo when you want baseline A2A interoperability plus your own security controls at the adapter or gateway layer.

## Deployment Precondition

A2AWall is a policy enforcement point. It protects an agent only if that agent
cannot be reached without passing through the gateway. Bind the wrapped agents to
a loopback interface or a private network, and let only the gateway reach them.
A caller that can open a connection to the agent directly bypasses every control
in this repo.

The gateway authenticates callers and then passes the resolved principal to the
agent in-process. It does not sign or otherwise authenticate the hop to a remote
agent, so a remote agent must not treat gateway-supplied headers as proof of
identity unless that hop is itself authenticated, for example with mTLS.

## Start Here

- User guide: [docs/user-guide.html](https://nebullii.github.io/a2awall/user-guide.html)
- Documentation: [docs/index.html](https://nebullii.github.io/a2awall/)

## Quick Start

```bash
npm install
cp .env.example .env
npm test
npm run build
npm start
```

## Defining a Policy

The environment variables configure a single identity against the capability
policies that already exist. They cannot define new capabilities, and they never
derive scopes from the capability list: a grant derived from its own requirement
would make the scope check vacuous. Naming an unknown capability, omitting
`SECURITY_SCOPES`, or misspelling a trust tier stops the process at startup
rather than resolving to a more permissive default.

Define real capabilities in code and pass the policy to `createApp`:

```ts
import { createApp, hashToken, type SecurityPolicy } from "a2awall";

const policy: SecurityPolicy = {
  securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } },
  securityRequirements: [{ bearerAuth: [] }],
  approval: { tokenSha256: [hashToken(process.env.APPROVAL_TOKEN!)] },
  identities: [
    {
      principalId: "release-bot",
      tokenSha256: process.env.CALLER_TOKEN_SHA256!,
      scopes: ["agent:invoke", "agent:deploy"],
      trustTier: "privileged",
      allowedCapabilities: ["deploy"]
    }
  ],
  capabilityPolicies: {
    deploy: {
      name: "Deploy",
      description: "Deploys a build to a protected environment.",
      requiredScopes: ["agent:deploy"],
      requiredTrustTier: "privileged",
      riskLevel: "critical",
      approvalRequired: true,
      toolAccess: "bounded-write",
      allowedToolIds: ["deployment-api"],
      maxToolCalls: 1,
      maxRuntimeMs: 30_000,
      maxMessageCharacters: 2000,
      networkDomains: ["deploy.internal.example.com"]
    }
  },
  metadata: {
    audience: "release-pipeline",
    trustTier: "privileged",
    capabilityHeader: "x-agent-capability",
    capabilityMetadataKey: "capability",
    requestIdHeader: "x-request-id",
    approvalHeader: "x-approval-token"
  }
};

createApp({ baseUrl: "https://agent.example.com", securityPolicy: policy });
```

`createApp` validates the policy before it serves anything. Contradictions, such
as a critical capability with no approval gate or a capability that grants tool
access with no tool budget, are startup errors.

To verify a signed credential instead of an opaque token, supply an
`identityResolver` that validates the token and maps its claims onto an
identity. That is where issuer, audience and expiry belong.

## Declaring the Capability

A request names one capability, either in the `x-agent-capability` header or in
the A2A-native `message.metadata.capability`. If both are present they must
agree; a disagreement is rejected rather than resolved by precedence, because a
precedence rule is what allows a caller to be admitted under one capability and
executed under another. The executor reads the capability from the admission
decision, never from message metadata.

## A2A Conformance

- The security metadata is published through the A2A extension mechanism, as a
  URI-identified `AgentExtension` in `capabilities.extensions`, not as ad-hoc
  `x-` properties. Extension URI:
  `https://nebullii.github.io/a2awall/extensions/security-policy/v1`. It is
  declared `required: false`, so plain A2A clients interoperate unchanged; the
  gateway enforces the policy whether or not a client activates it.
- Per-skill authorization uses the spec's own `AgentSkill.security` field.
- The public card omits the caller allowlist. Scopes and schemes belong on the
  public card by design; an allowlist of principals is reconnaissance.
- Rejections carry the HTTP status the specification names for auth errors and,
  on the JSON-RPC binding, a well-formed JSON-RPC error object. A2A 1.0 assigns
  no JSON-RPC code for authorization failure, so A2AWall uses the reserved
  implementation range and avoids the codes A2A has already assigned.
- `protocolVersion` tracks what the pinned `@a2a-js/sdk` actually speaks (0.3.x).
  Upgrading to A2A 1.0 is a data-model migration, not a version bump, and is
  tracked separately.

## Package Use

Install locally in this repo:

```bash
npm install
```

If you later publish it:

```bash
npm install a2awall
```

## CLI

```bash
npm run build
npm run connect -- --url http://localhost:4000 --token dev-token --caller first-user --capability echo --message "hello secure a2a"
```

If installed as a package:

```bash
a2awall-connect --url http://localhost:4000 --token dev-token --caller first-user --capability echo --message "hello secure a2a"
```

## Adversarial Scenario

Three agents collaborate over A2A, each behind its own gateway, and the third is
compromised: it holds valid mesh credentials and turns them on its peers.

```bash
npm run scenario:adversarial   # runs the mesh, writes adversarial-results.json
npm run scenario:report        # renders adversarial-report.html from those results
```

The run exercises 24 attacks across admission, task ownership, the trusted
context boundary, retrieval and memory policy, the tool sandbox, the secure
runtime, delegation limits, and protocol handling, and it checks that legitimate
traffic still succeeds before and after. The report is generated from the results
file, so its figures cannot drift from the run. Screenshots of a run are in
`docs/adversarial-run/`.

What the scenario does not establish is written on the report itself: the
attacker is scripted rather than independent, the agents are deterministic, and
the tool sandbox evaluates policy rather than isolating a process.

## Verification

```bash
npm test          # unit and in-process tests, then end-to-end
npm run test:unit # src/test.ts only
npm run test:e2e  # boots dist/index.js and drives it over HTTP
node dist/smoke.js
```

The end-to-end suite starts the published entrypoint as a subprocess and exercises
it with the real A2A client, the installed CLI, and raw requests on both the
JSON-RPC and REST bindings. Checks that depend on the wire format belong there:
the two bindings encode the same message differently, so a policy check written
against one shape can silently pass everything on the other.
