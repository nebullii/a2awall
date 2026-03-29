# Security Roadmap

This repo is an A2A-compatible gateway and adapter, not just a transport wrapper.

The goal is to preserve baseline A2A interoperability while enforcing stronger security controls at the gateway and runtime layers.

## Design Principle

- A2A remains the discovery and transport contract.
- The gateway enforces identity, policy, trust, and admission.
- The runtime enforces sandbox and action constraints.
- Downstream systems enforce least privilege independently.

## Threat Model

This roadmap is organized around these attack classes:

1. Authorization and Control Hijacking
2. Critical Systems Interaction
3. Goal and Instruction Manipulation
4. Hallucination Exploitation
5. Impact Chain and Blast Radius
6. Knowledge Base Poisoning
7. Memory and Context Manipulation
8. Orchestration and Multi-Agent Exploitation
9. Resource and Service Exhaustion
10. Supply Chain and Dependency Attacks

## Phase 1: Gateway Admission Control

Status: implemented foundation

Build:

- policy-driven capability admission
- scope checks
- trust-tier checks
- approval gates
- message-size limits
- risk and tool-access metadata

Repo mapping:

- `src/security/policy.ts`
- `src/security/admission.ts`
- `src/security/middleware.ts`
- `src/a2a/executor.ts`

Threats addressed first:

- Authorization and Control Hijacking
- Impact Chain and Blast Radius
- Resource and Service Exhaustion

## Phase 2: Trusted Context Boundary

Status: implemented foundation

Build:

- explicit context envelopes for system, user, memory, retrieval, tool output, and peer-agent output
- trust labels and provenance metadata
- prompt hierarchy rules
- policy that prevents untrusted content from overriding trusted instructions

Repo mapping:

- `src/context/envelope.ts`
- `src/context/trust.ts`

Threats:

- Goal and Instruction Manipulation
- Memory and Context Manipulation
- Knowledge Base Poisoning
- Orchestration and Multi-Agent Exploitation

## Phase 3: Tool and Runtime Sandbox

Status: implemented foundation

Build:

- capability-to-tool mapping
- network, filesystem, and action allowlists
- approval requirements for privileged actions
- execution budgets and timeout envelopes
- action audit log

Repo mapping:

- `src/runtime/sandbox.ts`

Threats:

- Critical Systems Interaction
- Impact Chain and Blast Radius
- Resource and Service Exhaustion

## Phase 4: Output and Action Validation

Status: implemented foundation

Build:

- structured output validation
- high-risk action review gates
- evidence requirements for sensitive responses
- optional verifier stage before tool execution

Repo mapping:

- `src/validation/output.ts`

Threats:

- Hallucination Exploitation
- Critical Systems Interaction

## Phase 5: Memory and Retrieval Security

Status: implemented foundation

Build:

- signed or provenance-tagged memory entries
- per-tenant memory isolation
- retrieval source trust scoring
- ingestion quarantine for untrusted knowledge
- memory write policy by capability

Repo mapping:

- `src/memory/store.ts`
- `src/retrieval/policy.ts`

Threats:

- Knowledge Base Poisoning
- Memory and Context Manipulation

## Phase 6: Multi-Agent Control Plane

Status: implemented foundation

Build:

- delegation policy
- recursion and fan-out limits
- transitive trust propagation
- agent-to-agent audit chain
- peer-agent identity verification

Repo mapping:

- `src/orchestration/delegation.ts`

Threats:

- Orchestration and Multi-Agent Exploitation
- Impact Chain and Blast Radius

## Phase 7: Supply Chain and Dependency Hardening

Build:

- dependency review and lock discipline
- SBOM generation
- signed policy artifacts where possible
- protected prompt/policy update process
- trusted connector inventory

Threats:

- Supply Chain and Dependency Attacks

## Recommended Next Implementation Step

Integrate the new control layers into actual runtime execution and tool dispatch.

Reason:

- the foundations now exist as policy and evaluation modules
- the next step is binding them to real tool runners, memory backends, retrieval adapters, and delegated agent calls
- that is where the framework becomes operational instead of only evaluative
