/**
 * Renders the adversarial scenario's results as a standalone HTML page.
 *
 * Every figure on the page is read from adversarial-results.json, so the report
 * cannot drift from what the run actually produced.
 *
 * Run with: npm run scenario:report
 */
import { readFile, writeFile } from "node:fs/promises";

interface Attack {
  id: number;
  name: string;
  target: string;
  technique: string;
  expectation: string;
  layer: string;
  blocked: boolean;
  status: number | string;
  reason: string;
  evidence: string;
}

interface Report {
  generatedAt: string;
  summary: {
    attacks: number;
    blocked: number;
    allowed: number;
    legitimateFlows: number;
    auditEvents: number;
    denialsAudited: number;
  };
  legitimate: Array<{ step: string; from: string; to: string; result: string }>;
  attacks: Attack[];
  observations: Array<{ control: string; outcome: string; detail: string }>;
  audit: Array<Record<string, any>>;
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const LAYER_ORDER = [
  "admission",
  "task ownership",
  "trusted context",
  "retrieval + memory",
  "tool sandbox",
  "secure runtime",
  "delegation",
  "protocol"
];

function layerRank(layer: string): number {
  const index = LAYER_ORDER.indexOf(layer);
  return index === -1 ? LAYER_ORDER.length : index;
}

function renderAttackRow(attack: Attack): string {
  const gateway = typeof attack.status === "number" && attack.status >= 400;
  return `
      <tr>
        <td class="num">${attack.id}</td>
        <td>
          <div class="attack-name">${escapeHtml(attack.name)}</div>
          <div class="attack-technique">${escapeHtml(attack.technique)}</div>
        </td>
        <td><span class="layer">${escapeHtml(attack.layer)}</span></td>
        <td class="num"><span class="status ${gateway ? "status-http" : "status-deep"}">${escapeHtml(attack.status)}</span></td>
        <td><code>${escapeHtml(attack.reason || "-")}</code></td>
        <td><span class="verdict ${attack.blocked ? "held" : "breach"}">${attack.blocked ? "held" : "BREACH"}</span></td>
      </tr>`;
}

function renderLayerTally(attacks: Attack[]): string {
  const tally = new Map<string, { total: number; held: number }>();
  for (const attack of attacks) {
    const entry = tally.get(attack.layer) ?? { total: 0, held: 0 };
    entry.total += 1;
    if (attack.blocked) {
      entry.held += 1;
    }
    tally.set(attack.layer, entry);
  }

  const max = Math.max(...[...tally.values()].map((entry) => entry.total));

  return [...tally.entries()]
    .sort((left, right) => layerRank(left[0]) - layerRank(right[0]))
    .map(([layer, entry]) => {
      const width = Math.round((entry.total / max) * 100);
      return `
        <div class="tally-row">
          <div class="tally-label">${escapeHtml(layer)}</div>
          <div class="tally-track"><div class="tally-bar" style="width:${width}%"></div></div>
          <div class="tally-count">${entry.held}/${entry.total}</div>
        </div>`;
    })
    .join("");
}

function renderAuditRows(audit: Array<Record<string, any>>): string {
  return audit
    .filter((event) => event.event === "agent_request_denied")
    .map(
      (event) => `
      <tr>
        <td class="num"><span class="status status-http">${escapeHtml(event.statusCode)}</span></td>
        <td><code>${escapeHtml((event.reasons ?? []).join(", "))}</code></td>
        <td><code class="dim">${escapeHtml(event.jsonRpcMethod ?? "-")}</code></td>
        <td><code class="dim">${escapeHtml(event.path)}</code></td>
      </tr>`
    )
    .join("");
}

function renderObservations(
  observations: Array<{ control: string; outcome: string; detail: string }>
): string {
  const blocking = observations.filter((entry) => entry.outcome !== "reference-only" && entry.outcome !== "allowed");
  return blocking
    .map(
      (entry) => `
      <tr>
        <td><span class="layer">${escapeHtml(entry.control)}</span></td>
        <td><code>${escapeHtml(entry.outcome)}</code></td>
        <td class="detail">${escapeHtml(entry.detail)}</td>
      </tr>`
    )
    .join("");
}

function renderPage(report: Report): string {
  const { summary } = report;
  const atGateway = report.attacks.filter(
    (attack) => typeof attack.status === "number" && attack.status >= 400
  ).length;
  const belowGateway = summary.attacks - atGateway;
  const sorted = [...report.attacks].sort(
    (left, right) => layerRank(left.layer) - layerRank(right.layer) || left.id - right.id
  );
  const generated = new Date(report.generatedAt).toISOString().replace("T", " ").slice(0, 19);

  return `<title>A2AWall Adversarial Run</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
  /* Layout: a status band, the attack matrix grouped by defending layer, then the evidence it left behind. */
  :root {
    --bg: #f3f5f7;
    --surface: #ffffff;
    --surface-sunk: #eceff2;
    --line: #d5dbe1;
    --line-soft: #e4e9ed;
    --fg: #16202b;
    --fg-muted: #5a6875;
    --fg-faint: #8695a3;
    --accent: #0f6d8f;
    --accent-soft: #e0eff5;
    --held: #1c6b4b;
    --held-soft: #dff0e7;
    --breach: #a32218;
    --breach-soft: #fbe4e1;
    --deep: #7a5a12;
    --deep-soft: #f8eed6;
    --font-sans: "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif;
    --font-mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
    color-scheme: light;
  }

  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #10161c;
      --surface: #182028;
      --surface-sunk: #131a21;
      --line: #2c3945;
      --line-soft: #222d38;
      --fg: #e6edf3;
      --fg-muted: #a0aeba;
      --fg-faint: #76858f;
      --accent: #57b6d8;
      --accent-soft: #14323f;
      --held: #6cc79b;
      --held-soft: #14301f;
      --breach: #f08a7e;
      --breach-soft: #3a1714;
      --deep: #ddb15f;
      --deep-soft: #322710;
      color-scheme: dark;
    }
  }

  :root[data-theme="dark"] {
    --bg: #10161c;
    --surface: #182028;
    --surface-sunk: #131a21;
    --line: #2c3945;
    --line-soft: #222d38;
    --fg: #e6edf3;
    --fg-muted: #a0aeba;
    --fg-faint: #76858f;
    --accent: #57b6d8;
    --accent-soft: #14323f;
    --held: #6cc79b;
    --held-soft: #14301f;
    --breach: #f08a7e;
    --breach-soft: #3a1714;
    --deep: #ddb15f;
    --deep-soft: #322710;
    color-scheme: dark;
  }

  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }
  .wrap {
    max-width: 1080px;
    margin: 0 auto;
    padding-block: 40px 64px;
    padding-left: 20px;
    padding-right: 20px;
  }

  .eyebrow {
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
    margin: 0 0 10px;
  }
  h1 {
    font-size: clamp(26px, 4.2vw, 38px);
    line-height: 1.12;
    letter-spacing: -0.02em;
    font-weight: 600;
    margin: 0 0 12px;
    text-wrap: balance;
  }
  .standfirst {
    font-size: 16px;
    color: var(--fg-muted);
    max-width: 64ch;
    margin: 0 0 8px;
  }
  .meta {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--fg-faint);
    margin: 0;
  }

  h2 {
    font-size: 13px;
    font-family: var(--font-mono);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--fg-muted);
    font-weight: 600;
    margin: 0 0 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--line);
  }
  section { margin-top: 44px; }
  p { margin: 0 0 12px; max-width: 68ch; }

  /* Status band */
  .band {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1px;
    background: var(--line);
    border: 1px solid var(--line);
    border-radius: 4px;
    overflow: hidden;
    margin-top: 28px;
  }
  .stat { background: var(--surface); padding: 16px 18px; }
  .stat-value {
    font-family: var(--font-mono);
    font-size: 26px;
    font-weight: 600;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    line-height: 1.1;
  }
  .stat-value.ok { color: var(--held); }
  .stat-label {
    font-size: 11.5px;
    color: var(--fg-muted);
    margin-top: 4px;
  }

  .verdict-strip {
    margin-top: 1px;
    background: var(--held-soft);
    border: 1px solid var(--line);
    border-top: none;
    border-radius: 0 0 4px 4px;
    padding: 12px 18px;
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--held);
  }
  .verdict-strip.bad { background: var(--breach-soft); color: var(--breach); }

  /* Topology */
  .topology {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 14px;
  }
  .node {
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 14px 16px;
  }
  .node.rogue { border-color: var(--breach); background: var(--breach-soft); }
  .node-name {
    font-family: var(--font-mono);
    font-size: 13px;
    font-weight: 600;
  }
  .node.rogue .node-name { color: var(--breach); }
  .node-role { font-size: 12px; color: var(--fg-muted); margin-top: 2px; }
  .node-tier {
    display: inline-block;
    margin-top: 10px;
    font-family: var(--font-mono);
    font-size: 10.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 2px;
    background: var(--surface-sunk);
    color: var(--fg-muted);
    border: 1px solid var(--line-soft);
  }
  .node.rogue .node-tier { background: var(--surface); color: var(--breach); border-color: var(--breach); }

  /* Tables */
  .table-scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 4px; background: var(--surface); }
  table { width: 100%; border-collapse: collapse; min-width: 640px; }
  thead th {
    text-align: left;
    font-family: var(--font-mono);
    font-size: 10.5px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--fg-faint);
    font-weight: 600;
    padding: 10px 12px;
    background: var(--surface-sunk);
    border-bottom: 1px solid var(--line);
    white-space: nowrap;
  }
  tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--line-soft);
    vertical-align: top;
    min-width: 0;
  }
  tbody tr:last-child td { border-bottom: none; }
  td.num { font-family: var(--font-mono); font-variant-numeric: tabular-nums; white-space: nowrap; color: var(--fg-faint); }
  .attack-name { font-weight: 500; }
  .attack-technique { font-size: 12px; color: var(--fg-muted); margin-top: 2px; }
  td.detail { font-size: 12px; color: var(--fg-muted); }
  code {
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--fg);
    word-break: break-word;
  }
  code.dim { color: var(--fg-faint); }

  .layer {
    font-family: var(--font-mono);
    font-size: 10.5px;
    letter-spacing: 0.04em;
    padding: 2px 7px;
    border-radius: 2px;
    background: var(--accent-soft);
    color: var(--accent);
    white-space: nowrap;
  }
  .status {
    font-family: var(--font-mono);
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 2px;
    font-size: 11.5px;
  }
  .status-http { background: var(--accent-soft); color: var(--accent); }
  .status-deep { background: var(--deep-soft); color: var(--deep); }
  .verdict {
    font-family: var(--font-mono);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 2px;
    white-space: nowrap;
  }
  .verdict.held { background: var(--held-soft); color: var(--held); }
  .verdict.breach { background: var(--breach-soft); color: var(--breach); }

  /* Layer tally */
  .tally { display: flex; flex-direction: column; gap: 8px; }
  .tally-row { display: grid; grid-template-columns: minmax(110px, 168px) 1fr auto; gap: 12px; align-items: center; }
  .tally-label { font-family: var(--font-mono); font-size: 11.5px; color: var(--fg-muted); min-width: 0; }
  .tally-track { background: var(--surface-sunk); border-radius: 2px; height: 16px; border: 1px solid var(--line-soft); }
  .tally-bar { background: var(--accent); height: 100%; border-radius: 1px; }
  .tally-count { font-family: var(--font-mono); font-size: 11.5px; font-variant-numeric: tabular-nums; color: var(--held); }

  .flows { display: flex; flex-direction: column; gap: 6px; }
  .flow {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 12px;
    align-items: baseline;
    background: var(--surface);
    border: 1px solid var(--line-soft);
    border-radius: 3px;
    padding: 9px 12px;
  }
  .flow-step { font-size: 13px; min-width: 0; }
  .flow-hop { font-family: var(--font-mono); font-size: 11px; color: var(--fg-faint); }
  .flow-result { font-family: var(--font-mono); font-size: 11.5px; color: var(--held); white-space: nowrap; }

  .caveats {
    background: var(--surface-sunk);
    border: 1px solid var(--line);
    border-left: 3px solid var(--deep);
    border-radius: 3px;
    padding: 16px 18px;
  }
  .caveats ul { margin: 0; padding-left: 18px; }
  .caveats li { margin-bottom: 7px; color: var(--fg-muted); font-size: 13px; }
  .caveats li:last-child { margin-bottom: 0; }
  .caveats strong { color: var(--fg); font-weight: 600; }

  @media (max-width: 560px) {
    .tally-row { grid-template-columns: 1fr auto; }
    .tally-track { display: none; }
    .flow { grid-template-columns: 1fr; }
  }
</style>

<div class="wrap">
  <p class="eyebrow">A2AWall / adversarial run</p>
  <h1>Three agents, one of them compromised</h1>
  <p class="standfirst">
    Three A2A agents collaborate, each behind its own A2AWall gateway. The third holds
    valid credentials for the mesh and turns them against its peers. Every figure below
    comes from the run recorded in <code>adversarial-results.json</code>.
  </p>
  <p class="meta">run ${escapeHtml(generated)}Z &middot; scenario: src/scenarios/adversarial.ts</p>

  <div class="band">
    <div class="stat">
      <div class="stat-value ok">${summary.blocked}/${summary.attacks}</div>
      <div class="stat-label">attacks refused</div>
    </div>
    <div class="stat">
      <div class="stat-value">${atGateway}</div>
      <div class="stat-label">refused at the gateway</div>
    </div>
    <div class="stat">
      <div class="stat-value">${belowGateway}</div>
      <div class="stat-label">admitted, refused deeper</div>
    </div>
    <div class="stat">
      <div class="stat-value">${summary.legitimateFlows}</div>
      <div class="stat-label">legitimate flows unaffected</div>
    </div>
    <div class="stat">
      <div class="stat-value">${summary.denialsAudited}</div>
      <div class="stat-label">denials in the audit log</div>
    </div>
  </div>
  <div class="verdict-strip${summary.allowed > 0 ? " bad" : ""}">
    ${
      summary.allowed > 0
        ? `${summary.allowed} attack(s) reached the agent. See the matrix.`
        : `No attack reached agent logic. ${belowGateway} were admitted as well-formed requests and stopped by a control below the gateway.`
    }
  </div>

  <section>
    <h2>The mesh</h2>
    <div class="topology">
      <div class="node">
        <div class="node-name">coordinator</div>
        <div class="node-role">Plans work and delegates it to peers.</div>
        <div class="node-tier">internal</div>
      </div>
      <div class="node">
        <div class="node-name">researcher</div>
        <div class="node-role">Retrieves reference material through sandboxed tools.</div>
        <div class="node-tier">partner-gated</div>
      </div>
      <div class="node rogue">
        <div class="node-name">notetaker &mdash; compromised</div>
        <div class="node-role">A third-party agent with real credentials, used to attack the other two.</div>
        <div class="node-tier">public</div>
      </div>
    </div>
  </section>

  <section>
    <h2>Which layer refused what</h2>
    <p>
      Attacks are grouped by the control that stopped them. A request refused at the
      gateway never reached the agent; one refused below the gateway was a well-formed,
      authorized request whose <em>content</em> was hostile, which is the case the
      admission layer cannot decide on its own.
    </p>
    <div class="tally">${renderLayerTally(report.attacks)}</div>
  </section>

  <section>
    <h2>Attack matrix</h2>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Attack</th>
            <th>Refused by</th>
            <th>Status</th>
            <th>Reason</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>${sorted.map(renderAttackRow).join("")}
        </tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Controls below the gateway</h2>
    <p>
      These decisions were made after the request was admitted, by the modules the
      roadmap describes as policy evaluators. Here they run as controls in the request
      path rather than as libraries.
    </p>
    <div class="table-scroll">
      <table>
        <thead>
          <tr><th>Control</th><th>Outcome</th><th>Detail</th></tr>
        </thead>
        <tbody>${renderObservations(report.observations)}
        </tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Audit trail</h2>
    <p>
      The gateway returns a generic reason to the caller and records the precise one
      internally. A cross-principal task read answers <code>TASK_NOT_FOUND</code> so that
      the task's existence cannot be probed, while the log keeps
      <code>task_not_owned</code>.
    </p>
    <div class="table-scroll">
      <table>
        <thead>
          <tr><th>Status</th><th>Recorded reason</th><th>Method</th><th>Gateway / path</th></tr>
        </thead>
        <tbody>${renderAuditRows(report.audit)}
        </tbody>
      </table>
    </div>
  </section>

  <section>
    <h2>Legitimate traffic</h2>
    <p>A control that blocks everything is not a control. These flows ran before and after the attack phase.</p>
    <div class="flows">
      ${report.legitimate
        .map(
          (flow) => `<div class="flow">
        <div class="flow-step">${escapeHtml(flow.step)}<div class="flow-hop">${escapeHtml(flow.from)} &rarr; ${escapeHtml(flow.to)}</div></div>
        <div class="flow-result">${escapeHtml(flow.result)}</div>
      </div>`
        )
        .join("\n      ")}
    </div>
  </section>

  <section>
    <h2>What this run does not show</h2>
    <div class="caveats">
      <ul>
        <li><strong>The attacker is scripted, not independent.</strong> These are the attacks
          A2AWall was built to refuse, written by the same author. A real assessment needs
          an adversary who did not read the source.</li>
        <li><strong>The agents are deterministic.</strong> No model is in the loop, so the
          prompt-injection case tests the trusted context boundary's classification, not a
          model's resistance to persuasion.</li>
        <li><strong>The tool sandbox is a policy evaluator, not isolation.</strong> Tools run
          in the gateway process. The SSRF and traversal cases were refused before any I/O,
          which is not the same as containing a tool that misbehaves.</li>
        <li><strong>Lexical checks only.</strong> Host and path allowlists are evaluated as
          text. A hostname that resolves to a blocked address, or a symlink out of an allowed
          directory, is the responsibility of the component performing the I/O.</li>
        <li><strong>Single process, in-memory state.</strong> Task ownership is known only to
          the instance that admitted the request. A multi-instance deployment needs a shared
          store.</li>
        <li><strong>Credentials are static bearer tokens.</strong> A signed-token verifier is
          an extension point, not something shipped here.</li>
      </ul>
    </div>
  </section>
</div>
`;
}

const raw = await readFile("adversarial-results.json", "utf8");
const report = JSON.parse(raw) as Report;
await writeFile("adversarial-report.html", renderPage(report), "utf8");
console.log(
  `wrote adversarial-report.html (${report.summary.blocked}/${report.summary.attacks} attacks refused)`
);
