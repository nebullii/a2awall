# A2AWall x NEST Integration Test Report

**Date:** 2026-04-17
**Version:** A2AWall v0.2.0 / NEST v2.0.0
**Environment:** macOS Darwin 25.3.0, Node.js, Python 3
**Test Runner:** `demo/run-nest-test.ts`, `demo/benchmark.ts`

---

## 1. Executive Summary

A2AWall was tested as a security gateway for 5 NEST (NANDA Sandbox and Testbed) agents communicating over the A2A protocol. All 18 functional tests passed. Performance benchmarks show the security layer adds 0.25ms (p50) per request — negligible for production agent workloads.

**Verdict:** A2AWall integrates with NEST agents without protocol changes, enforces its gateway admission and routing controls, and introduces sub-millisecond overhead. The other security layers were not in the request path for this run. See Sections 5.2 and 6.

---

## 2. Test Architecture

```
                        A2A Protocol                      A2A Protocol
                     ┌──────────────┐                  ┌──────────────┐
                     │              │                  │              │
  Client ──────────► │   A2AWall    │ ──── routes ───► │  NEST Agent  │
  (curl / test.ts)   │  Gateway     │                  │  (Python)    │
                     │  port 4000   │                  │              │
                     │              │                  │              │
                     │ ┌──────────┐ │      ┌───────────┴──────────────┤
                     │ │ Bearer   │ │      │ researcher    :6001      │
                     │ │ Auth     │ │      │ analyst       :6002      │
                     │ ├──────────┤ │      │ writer        :6003      │
                     │ │ Scope    │ │      │ reviewer      :6004      │
                     │ │ Check    │ │      │ coordinator   :6005      │
                     │ ├──────────┤ │      └──────────────────────────┘
                     │ │ Trust    │ │
                     │ │ Tier     │ │
                     │ ├──────────┤ │
                     │ │ Capabil. │ │
                     │ │ Routing  │ │
                     │ └──────────┘ │
                     └──────────────┘
```

### NEST Agents Under Test

| Agent | ID | Port | Capabilities | Domain |
|-------|----|------|-------------|--------|
| Research Agent | researcher | 6001 | research, summarize | Information gathering |
| Data Analyst Agent | analyst | 6002 | analyze, statistics | Statistical analysis |
| Writer Agent | writer | 6003 | write, edit | Content creation |
| Review Agent | reviewer | 6004 | review, validate | Quality assurance |
| Coordinator Agent | coordinator | 6005 | coordinate, delegate | Multi-agent orchestration |

### Security Policy Configuration

| Identity | Token | Trust Tier | Allowed Capabilities |
|----------|-------|-----------|---------------------|
| demo-caller | `nest-demo-token` | internal | All 10 capabilities |
| public-caller | `public-token` | public | research, summarize only |

| Capability | Required Trust Tier | Risk Level |
|-----------|-------------------|-----------|
| research, summarize | public | low |
| analyze, statistics, write, edit, review, validate | partner | low |
| coordinate, delegate | partner | medium |

---

## 3. Functional Test Results

**Total: 18/18 PASSED**

### 3.1 Gateway Infrastructure

| # | Test | Expected | Result |
|---|------|----------|--------|
| 1 | Health endpoint returns 200 | HTTP 200 + agent metadata | PASS |
| 2 | Health reports all capabilities | 10 capabilities listed | PASS |
| 3 | Agent card accessible at `/.well-known/agent-card.json` | Valid A2A agent card | PASS |
| 4 | Agent card lists all NEST agent skills | 10 skills with security extensions | PASS |

### 3.2 Security Enforcement

| # | Test | Expected | Result |
|---|------|----------|--------|
| 5 | Request without bearer token | HTTP 401 Unauthorized | PASS |
| 6 | Request with unknown capability | HTTP 403 Forbidden | PASS |
| 7 | Public caller → research (allowed tier) | HTTP 200 + response | PASS |
| 8 | Public caller → coordinate (insufficient tier) | HTTP 403 Forbidden | PASS |

### 3.3 Agent Routing

| # | Test | Expected | Result |
|---|------|----------|--------|
| 9 | Route to Research Agent via `research` | 200 + researcher response | PASS |
| 10 | Route to Analyst Agent via `analyze` | 200 + analyst response | PASS |
| 11 | Route to Writer Agent via `write` | 200 + writer response | PASS |
| 12 | Route to Review Agent via `review` | 200 + reviewer response | PASS |
| 13 | Route to Coordinator Agent via `coordinate` | 200 + coordinator response | PASS |

### 3.4 Multi-Agent Pipeline

| # | Test | Expected | Result |
|---|------|----------|--------|
| 14 | Pipeline step: coordinate | Coordinator produces plan | PASS |
| 15 | Pipeline step: research | Researcher gathers data | PASS |
| 16 | Pipeline step: analyze | Analyst processes findings | PASS |
| 17 | Pipeline step: write | Writer drafts report | PASS |
| 18 | Pipeline step: review | Reviewer validates output | PASS |

---

## 4. Performance Benchmark Results

### 4.1 Methodology

- **Warmup:** 50 requests discarded before measurement
- **Samples:** 500 requests per test
- **Concurrency levels:** 1, 10, 50, 100
- **Agent logic:** Deterministic (no LLM calls) to isolate infrastructure overhead
- **Environment:** Localhost (no network latency)

### 4.2 Sequential Latency (Single Client)

| Path | p50 | p95 | p99 | Mean |
|------|-----|-----|-----|------|
| Direct → NEST (baseline) | 0.51 ms | 0.61 ms | 1.01 ms | 0.53 ms |
| Through A2AWall gateway | 0.76 ms | 0.96 ms | 2.20 ms | 0.80 ms |

**A2AWall overhead:**

| Metric | Value |
|--------|-------|
| p50 overhead | +0.25 ms |
| p95 overhead | +0.35 ms |
| p99 overhead | +1.19 ms |
| Mean overhead | +0.27 ms |
| Relative overhead | +51.7% of baseline |

> Note: The 51.7% relative figure reflects the overhead as a percentage of a
> sub-millisecond baseline. In real-world use with LLM calls (500-3000ms),
> 0.25ms represents <0.05% overhead.

### 4.3 Concurrent Throughput

| Concurrency | Direct (req/s) | Gateway (req/s) | Overhead |
|-------------|---------------|-----------------|----------|
| 1 | 1,955 | 1,403 | -28.2% |
| 10 | 3,193 | 3,062 | -4.1% |
| 50 | 3,257 | 2,845 | -12.7% |
| 100 | 3,039 | 2,844 | -6.4% |

### 4.4 Latency Distribution Under Load

**Direct → NEST:**

| Concurrency | p50 | p95 | p99 |
|-------------|-----|-----|-----|
| 1 | 0.50 ms | 0.58 ms | 0.79 ms |
| 10 | 2.62 ms | 4.20 ms | 19.41 ms |
| 50 | 13.06 ms | 31.92 ms | 34.83 ms |
| 100 | 27.39 ms | 51.35 ms | 56.49 ms |

**Through A2AWall:**

| Concurrency | p50 | p95 | p99 |
|-------------|-----|-----|-----|
| 1 | 0.68 ms | 0.86 ms | 1.18 ms |
| 10 | 2.91 ms | 6.26 ms | 7.62 ms |
| 50 | 14.82 ms | 34.19 ms | 37.69 ms |
| 100 | 30.09 ms | 58.62 ms | 61.85 ms |

---

## 5. Key Findings

### 5.1 Protocol Compatibility

A2AWall and NEST both implement the A2A protocol. A2AWall acts as a transparent proxy — NEST agents receive standard A2A JSON-RPC requests and are unaware of the gateway. No modifications to NEST agent code are required.

### 5.2 Gateway Admission and Routing

This run exercised the gateway admission and routing path. It did not exercise the other
A2AWall security layers. The controls below were in the request path and behaved as
configured.

| Control | Exercised | Observed |
|---------|-----------|----------|
| Admission control (bearer auth) | Yes | Rejects missing/invalid tokens |
| Capability scoping | Yes | Rejects unknown capabilities |
| Trust tier enforcement | Yes | Public callers blocked from partner-tier capabilities |
| Capability→agent routing | Yes | All 5 agents correctly targeted |
| Risk-level metadata | Yes | coordinate/delegate tagged as medium risk |
| Multi-agent pipeline | Yes | 5-step workflow completed through gateway |

These six rows are not the six security layers named in the project documentation. They are
controls inside layer 1, gateway admission control, plus the capability routing and risk
metadata that sit alongside it. Risk-level metadata was observed as metadata only. Nothing
in this run acted on it.

#### Layers not exercised

| Layer | Status in this run |
|-------|--------------------|
| Trusted context boundary (`src/context/`) | Not in the request path. No context envelopes were constructed |
| Secure runtime and tools (`src/runtime/`) | Not in the request path. No tool execution occurred |
| Output and action validation (`src/validation/`) | Not in the request path. Agent responses were passed through unvalidated |
| Memory security (`src/memory/`) | Not in the request path. No memory backend was configured |
| Retrieval provenance (`src/retrieval/`) | Not in the request path. No retrieval occurred |
| Delegation controls (`src/orchestration/`) | Not exercised. The pipeline was driven by the test client, not by coordinator-initiated delegation |

No claim is made about these layers on the basis of this run. See Section 6 for the full
tested and not-tested breakdown, which lists the same gaps.

### 5.3 Performance Characteristics

1. **Fixed overhead is small:** 0.25ms per request covers bearer auth validation, scope lookup, trust-tier check, capability resolution, and HTTP proxy hop.

2. **Throughput scales with concurrency:** Gateway sustains ~2,800 req/s at c=100, within 6% of direct access. The bottleneck is the NEST agent (Python/uvicorn), not A2AWall.

3. **Tail latency is bounded:** p99 at c=100 is 61.85ms through the gateway vs 56.49ms direct — a 5ms delta that would be indistinguishable in production with real LLM workloads.

### 5.4 Known Issues at Time of Testing

This run predates fixes to capability resolution. The capability resolution path was changed
after these results were recorded, so the admission and routing results in Sections 3.2, 3.3,
and 5.2 describe the earlier behaviour.

The report should be re-run once those changes land. Until then, treat the functional results
as a record of the tested build rather than of current behaviour. The Section 4 benchmark
numbers were measured on the same build and carry the same caveat.

---

## 6. Limitations and Scope

### Tested

- [x] 5 NEST agents with 10 distinct capabilities
- [x] Bearer token authentication enforcement
- [x] Capability-based routing and scoping
- [x] Trust-tier graduated access control
- [x] Sequential and concurrent performance under load
- [x] Multi-agent pipeline workflow
- [x] A2A agent card discovery with security extensions

### Not Tested

- [ ] Real LLM-backed agent logic (deterministic fallback used)
- [ ] True delegation chains (coordinator actually invoking other agents)
- [ ] NEST Ed25519 signing combined with A2AWall bearer auth
- [ ] Dynamic discovery via Nanda Index → A2AWall routing
- [ ] Horizontal scaling (multiple A2AWall instances)
- [ ] Tool sandbox enforcement with NEST tool runtime
- [ ] Memory/retrieval security with NEST data stores
- [ ] Output validation with real agent-generated content
- [ ] Persistent task store (Redis/Postgres)
- [ ] Network latency (cross-host deployment)

---

## 7. How to Reproduce

### Prerequisites

```bash
# Clone both repositories
git clone https://github.com/user/a2awall.git
git clone https://github.com/projnanda/NEST-beta.git

# Install A2AWall
cd a2awall && npm install && npm run build

# Install NEST
cd ../NEST-beta && pip3 install -e .
```

### Run Functional Tests

```bash
cd a2awall

# 5 agents (default)
npx tsx demo/run-nest-test.ts 5

# 2 agents
npx tsx demo/run-nest-test.ts 2
```

### Run Benchmark

```bash
npx tsx demo/benchmark.ts 5
```

### Run Interactively

```bash
# Terminal 1: Start NEST agents
python3 demo/nest_agents.py 5

# Terminal 2: Start A2AWall gateway
npm start

# Terminal 3: Send requests
curl -s http://localhost:4000/a2a/jsonrpc \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-token' \
  -H 'X-Agent-Capability: research' \
  -d '{
    "jsonrpc":"2.0","id":"1","method":"message/send",
    "params":{"message":{
      "kind":"message","messageId":"m1","role":"user",
      "parts":[{"kind":"text","text":"What are A2A security patterns?"}],
      "metadata":{"capability":"research"}
    }}
  }' | python3 -m json.tool
```

---

## 8. Files

| File | Purpose |
|------|---------|
| `demo/nest_agents.py` | Starts N NEST agents with distinct roles |
| `demo/nest-gateway-agent.ts` | A2AWall CustomAgent proxy to NEST agents |
| `demo/run-nest-test.ts` | Functional test suite (18 tests) |
| `demo/benchmark.ts` | Latency and throughput benchmark |
| `demo/TEST_REPORT.md` | This report |

---

## 9. Conclusion

A2AWall successfully integrates with NEST agents as a transparent A2A-compatible security gateway. The integration requires zero changes to NEST agent code, enforces graduated security policies across capabilities and trust tiers, and adds sub-millisecond overhead that is negligible in production agent workloads. The architecture positions A2AWall as the security enforcement layer complementing NEST's agent runtime and Nanda Index's discovery layer.
