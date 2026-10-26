import { DefaultRequestHandler, InMemoryTaskStore, ServerCallContext } from "@a2a-js/sdk/server";
import type { MessageSendParams } from "@a2a-js/sdk";
import { CustomAgentExecutor, GatewayPrincipal, createAgentCard } from "./a2a/executor.js";
import { createExampleAgent } from "./core/example-agent.js";
import { createSecurityMiddleware } from "./security/middleware.js";
import { defaultSecurityPolicy } from "./security/policy.js";

async function verifyMiddleware() {
  const middleware = createSecurityMiddleware(defaultSecurityPolicy);

  const unauthorizedResponse = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value;
    }
  };

  let unauthorizedNextCalled = false;
  await middleware(
    {
      header: () => undefined,
      headers: {},
      path: "/a2a/jsonrpc",
      method: "POST"
    } as never,
    unauthorizedResponse as never,
    () => {
      unauthorizedNextCalled = true;
    }
  );

  console.log("middleware unauthorized", unauthorizedResponse.statusCode, unauthorizedNextCalled);

  const forbiddenResponse = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value;
    }
  };

  let forbiddenNextCalled = false;
  await middleware(
    {
      header(name: string) {
        if (name === "authorization") return "Bearer dev-token";
        if (name === "x-agent-capability") return "admin";
        return undefined;
      },
      body: { jsonrpc: "2.0", id: "1", method: "message/send" },
      headers: {},
      path: "/a2a/jsonrpc",
      method: "POST"
    } as never,
    forbiddenResponse as never,
    () => {
      forbiddenNextCalled = true;
    }
  );

  console.log("middleware forbidden", forbiddenResponse.statusCode, forbiddenNextCalled);

  const authorizedResponse = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value;
    }
  };

  let authorizedNextCalled = false;
  await middleware(
    {
      header(name: string) {
        if (name === "authorization") return "Bearer dev-token";
        if (name === "x-agent-capability") return "echo";
        if (name === "x-request-id") return "req-123";
        return undefined;
      },
      body: { jsonrpc: "2.0", id: "1", method: "message/send" },
      headers: {},
      path: "/a2a/jsonrpc",
      method: "POST"
    } as never,
    authorizedResponse as never,
    () => {
      authorizedNextCalled = true;
    }
  );

  console.log("middleware authorized", authorizedResponse.statusCode, authorizedNextCalled);
}

async function verifyRequestHandler() {
  const agent = createExampleAgent(defaultSecurityPolicy);
  const agentCard = createAgentCard("http://localhost:4000", agent, defaultSecurityPolicy);
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    new InMemoryTaskStore(),
    new CustomAgentExecutor(agent)
  );

  const resolvedAgentCard = await requestHandler.getAgentCard();
  console.log("agent-card", resolvedAgentCard.name, resolvedAgentCard.url);
  console.log(
    "agent-card-security",
    JSON.stringify({
      security: agentCard.security,
      securitySchemes: agentCard.securitySchemes,
      skillSecurity: agentCard.skills[0]?.security,
      securityExtension: agentCard.capabilities.extensions?.[0]?.uri
    })
  );

  const params: MessageSendParams = {
    message: {
      kind: "message",
      messageId: "msg-1",
      role: "user",
      parts: [{ kind: "text", text: "hello" }],
      metadata: {
        requestId: "req-456",
        capability: "echo"
      }
    }
  };

  const response = await requestHandler.sendMessage(
    params,
    new ServerCallContext(undefined, new GatewayPrincipal("smoke-caller", "echo", "req-456"))
  );
  if (response.kind !== "message") {
    throw new Error(`Expected a direct message response, got ${response.kind}`);
  }

  const firstPart = response.parts[0];
  if (firstPart?.kind !== "text") {
    throw new Error("Expected a text response.");
  }

  console.log("a2a-response", firstPart.text);

  const templateResponse = await requestHandler.sendMessage(
    {
      message: {
        kind: "message",
        messageId: "msg-2",
        role: "user",
        parts: [{ kind: "text", text: "hello via tool runtime" }],
        metadata: { requestId: "req-789" }
      }
    },
    new ServerCallContext(
      undefined,
      new GatewayPrincipal("smoke-caller", "template-echo", "req-789")
    )
  );

  if (templateResponse.kind !== "message") {
    throw new Error(`Expected a direct message response, got ${templateResponse.kind}`);
  }

  const templatePart = templateResponse.parts[0];
  if (templatePart?.kind !== "text") {
    throw new Error("Expected a text response from template-echo.");
  }

  console.log("a2a-tool-response", templatePart.text);
}

await verifyMiddleware();
await verifyRequestHandler();
