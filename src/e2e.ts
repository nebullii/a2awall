/**
 * End-to-end checks against a real server process.
 *
 * `src/test.ts` covers units and two in-process HTTP cases. This file boots the
 * actual `dist/index.js` entrypoint as a subprocess and drives it over the wire
 * with the real A2A client, the real CLI binary, and raw HTTP on both the
 * JSON-RPC and REST bindings.
 *
 * It exists because transport-shape bugs are invisible to in-process tests: the
 * two bindings use different wire formats for the same message, and an
 * admission check written against one of them silently passes everything on the
 * other.
 */
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";

const PORT = 4900 + Math.floor(Math.random() * 90);
const BASE_URL = `http://127.0.0.1:${PORT}`;

interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
}

const results: CheckResult[] = [];

function check(name: string, passed: boolean, detail = "") {
  results.push({ name, passed, detail });
  console.log(`${passed ? "pass" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
}

let serverLog = "";

async function startServer(): Promise<ChildProcess> {
  const server = spawn(process.execPath, ["dist/index.js"], {
    env: { ...process.env, PORT: String(PORT), BASE_URL, NODE_ENV: "development" },
    stdio: ["ignore", "pipe", "pipe"]
  });

  server.stdout?.on("data", (chunk) => {
    serverLog += String(chunk);
  });
  server.stderr?.on("data", (chunk) => {
    serverLog += String(chunk);
  });

  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await fetch(`${BASE_URL}/health`);
      return server;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  throw new Error(`Server did not start on ${BASE_URL}. Log:\n${serverLog}`);
}

function jsonRpc(capability: string | undefined, text = "payload") {
  return {
    jsonrpc: "2.0",
    id: "1",
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: "m1",
        role: "user",
        parts: [{ kind: "text", text }],
        metadata: capability ? { capability } : undefined
      }
    }
  };
}

async function postJsonRpc(headers: Record<string, string>, body: unknown) {
  const response = await fetch(`${BASE_URL}/a2a/jsonrpc`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body)
  });

  return { status: response.status, headers: response.headers, text: await response.text() };
}

/**
 * The REST binding decodes proto-JSON: the message sits at the top level, the
 * role is an enum name, parts are called `content`, and there is no `kind`.
 */
async function postRest(
  headers: Record<string, string>,
  message: Record<string, unknown>
) {
  const response = await fetch(`${BASE_URL}/a2a/rest/v1/message:send`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ message })
  });

  return { status: response.status, text: await response.text() };
}

const authorized = {
  authorization: "Bearer dev-token",
  "x-agent-capability": "echo"
};

async function checkDiscovery() {
  const health = (await (await fetch(`${BASE_URL}/health`)).json()) as {
    ok: boolean;
    capabilities: string[];
  };
  check("the published entrypoint boots and serves /health", health.ok === true);

  const cardResponse = await fetch(`${BASE_URL}/.well-known/agent-card.json`);
  const card = (await cardResponse.json()) as Record<string, any>;
  check(
    "the public Agent Card is served without credentials",
    cardResponse.status === 200 && card.name === "Echo Agent"
  );

  const extension = (card.capabilities?.extensions ?? []).find((entry: { uri: string }) =>
    entry.uri.includes("a2awall")
  );
  check("the security extension survives the HTTP round trip", Boolean(extension));
  check(
    "the card carries no ad-hoc x- properties",
    Object.keys(card).filter((key) => key.toLowerCase().startsWith("x-")).length === 0
  );
  check(
    "the public card does not publish the caller allowlist",
    !JSON.stringify(card).includes("allowedPrincipals")
  );
}

async function checkRealClient() {
  const { connectToAgent, sendTextToAgent } = await import("./client/connect.js");

  const connection = await connectToAgent({
    baseUrl: BASE_URL,
    bearerToken: "dev-token",
    callerId: "e2e-client"
  });
  check("the A2A client resolves the card and selects a transport", connection.card.name === "Echo Agent");

  const echoed = await sendTextToAgent(connection, {
    capability: "echo",
    message: "hello over the wire"
  });
  check("the A2A client invokes echo", /hello over the wire/.test(echoed.text), echoed.text);

  const templated = await sendTextToAgent(connection, {
    capability: "template-echo",
    message: "via tool runtime"
  });
  check(
    "the A2A client reaches the secure tool runtime",
    /\[template:template-echo\]/.test(templated.text),
    templated.text
  );

  let undeclared: unknown;
  try {
    await sendTextToAgent(connection, { message: "no capability declared" });
  } catch (error) {
    undeclared = error;
  }
  check("a request declaring no capability is refused", undeclared !== undefined);

  let badCredential: unknown;
  try {
    const attacker = await connectToAgent({
      baseUrl: BASE_URL,
      bearerToken: "wrong-token",
      callerId: "attacker"
    });
    await sendTextToAgent(attacker, { capability: "echo", message: "should not work" });
  } catch (error) {
    badCredential = error;
  }
  check("an invalid credential is refused", badCredential !== undefined);
}

async function checkJsonRpcBinding() {
  const conflict = await postJsonRpc(authorized, jsonRpc("template-echo"));
  const conflictBody = JSON.parse(conflict.text) as {
    jsonrpc: string;
    id: string;
    error: { code: number; data: { reason: string } };
  };
  check(
    "a capability declared twice with different values is refused",
    conflict.status === 400 && conflictBody.error.data.reason === "CAPABILITY_CONFLICT"
  );
  check(
    "the refusal is a well-formed JSON-RPC error object",
    conflictBody.jsonrpc === "2.0" &&
      conflictBody.id === "1" &&
      typeof conflictBody.error.code === "number"
  );

  const unauthenticated = await postJsonRpc({}, jsonRpc("echo"));
  check("an unauthenticated request is refused", unauthenticated.status === 401);
  check(
    "the refusal carries an authentication challenge",
    unauthenticated.headers.get("www-authenticate") === 'Bearer realm="a2awall"'
  );

  const oversizedFile = await postJsonRpc(authorized, {
    jsonrpc: "2.0",
    id: "1",
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: "m2",
        role: "user",
        parts: [{ kind: "file", file: { bytes: "A".repeat(9000) } }],
        metadata: { capability: "echo" }
      }
    }
  });
  check("the size limit counts file parts", oversizedFile.status === 413);

  const oversizedBody = await postJsonRpc({}, {
    jsonrpc: "2.0",
    id: "1",
    method: "message/send",
    params: { message: { parts: [{ kind: "text", text: "B".repeat(400 * 1024) }] } }
  });
  check(
    "an oversized body is refused before authentication",
    oversizedBody.status === 413 || oversizedBody.status === 400
  );
}

/**
 * The REST binding is a second wire format for the same policy. Every check
 * here has a JSON-RPC counterpart above, and the pairing is the point.
 */
async function checkRestBinding() {
  const admitted = await postRest(authorized, {
    messageId: "r1",
    role: "ROLE_USER",
    content: [{ text: "hello rest" }],
    metadata: { capability: "echo" }
  });
  check(
    "the REST binding admits an authorized request and preserves the text",
    (admitted.status === 200 || admitted.status === 201) && /hello rest/.test(admitted.text),
    `${admitted.status}`
  );

  const unauthenticated = await postRest({}, {
    messageId: "r2",
    role: "ROLE_USER",
    content: [{ text: "x" }],
    metadata: { capability: "echo" }
  });
  check("the REST binding refuses an unauthenticated request", unauthenticated.status === 401);
  check(
    "the REST refusal is not wrapped in a JSON-RPC envelope",
    !(JSON.parse(unauthenticated.text) as { jsonrpc?: string }).jsonrpc
  );

  const oversizedContent = await postRest(authorized, {
    messageId: "r3",
    role: "ROLE_USER",
    content: [{ text: "C".repeat(9000) }],
    metadata: { capability: "echo" }
  });
  check(
    "the size limit applies to proto-JSON `content` parts",
    oversizedContent.status === 413,
    `${oversizedContent.status}`
  );

  const oversizedParts = await postRest(authorized, {
    messageId: "r4",
    role: "ROLE_USER",
    parts: [{ kind: "text", text: "D".repeat(9000) }],
    metadata: { capability: "echo" }
  });
  check(
    "the size limit also applies to `parts` on the REST route",
    oversizedParts.status === 413,
    `${oversizedParts.status}`
  );

  const conflict = await postRest(authorized, {
    messageId: "r5",
    role: "ROLE_USER",
    content: [{ text: "x" }],
    metadata: { capability: "template-echo" }
  });
  check("a capability conflict is detected on the REST body shape", conflict.status === 400);
}

async function checkCli() {
  const cli = spawn(
    process.execPath,
    [
      "dist/cli/connect.js",
      "--url", BASE_URL,
      "--token", "dev-token",
      "--caller", "cli-user",
      "--capability", "echo",
      "--message", "hello from the cli"
    ],
    { stdio: ["ignore", "pipe", "pipe"] }
  );

  let output = "";
  cli.stdout?.on("data", (chunk) => {
    output += String(chunk);
  });
  cli.stderr?.on("data", (chunk) => {
    output += String(chunk);
  });

  const [code] = (await once(cli, "exit")) as [number];
  check(
    "the installed CLI round-trips against the live server",
    code === 0 && /hello from the cli/.test(output),
    `exit=${code}`
  );
}

function checkAuditTrail() {
  const events = serverLog
    .split("\n")
    .filter((line) => line.startsWith("{") && line.includes('"event"'))
    .flatMap((line) => {
      try {
        return [JSON.parse(line) as Record<string, any>];
      } catch {
        return [];
      }
    });

  check(
    "the server emits structured audit events for both outcomes",
    events.some((event) => event.event === "agent_request_admitted") &&
      events.some((event) => event.event === "agent_request_denied")
  );

  check(
    "the bypass attempt is recorded as a denial, with its reason",
    events.some(
      (event) =>
        event.event === "agent_request_denied" &&
        (event.reasons ?? []).includes("capability_conflict")
    )
  );

  // The original defect produced an audit record describing a different, safer
  // capability than the one that actually ran.
  check(
    "no admitted event pairs a capability with another capability's tool access",
    events
      .filter((event) => event.event === "agent_request_admitted")
      .every(
        (event) =>
          (event.capability === "echo" && event.toolAccess === "none") ||
          (event.capability === "template-echo" && event.toolAccess === "read-only")
      )
  );
}

const server = await startServer();

try {
  await checkDiscovery();
  await checkRealClient();
  await checkJsonRpcBinding();
  await checkRestBinding();
  await checkCli();
  checkAuditTrail();
} finally {
  server.kill("SIGTERM");
}

const failures = results.filter((result) => !result.passed);
console.log(`\n${results.length - failures.length}/${results.length} end-to-end checks passed`);

assert.deepEqual(
  failures.map((failure) => failure.name),
  [],
  "end-to-end checks failed"
);

console.log("e2e passed");
