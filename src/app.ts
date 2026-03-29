import express, { type Request } from "express";
import { DefaultRequestHandler, InMemoryTaskStore, type User } from "@a2a-js/sdk/server";
import { agentCardHandler, jsonRpcHandler, restHandler } from "@a2a-js/sdk/server/express";
import { AGENT_CARD_PATH, CustomAgentExecutor, createAgentCard } from "./a2a/executor.js";
import { type CustomAgent } from "./core/agent.js";
import { createExampleAgent } from "./core/example-agent.js";
import { createSecurityMiddleware } from "./security/middleware.js";
import { defaultSecurityPolicy, type SecurityPolicy } from "./security/policy.js";

export interface AppConfig {
  baseUrl: string;
  agent?: CustomAgent;
  securityPolicy?: SecurityPolicy;
}

class AuthenticatedUser implements User {
  constructor(private readonly name: string) {}

  get isAuthenticated(): boolean {
    return true;
  }

  get userName(): string {
    return this.name;
  }
}

async function buildUser(request: Request): Promise<User> {
  const callerId = request.header("x-caller-id") ?? "secured-caller";
  return new AuthenticatedUser(callerId);
}

export function createApp(config: AppConfig) {
  const securityPolicy = config.securityPolicy ?? defaultSecurityPolicy;
  const agent = config.agent ?? createExampleAgent(securityPolicy);
  const agentCard = createAgentCard(config.baseUrl, agent, securityPolicy);
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    new InMemoryTaskStore(),
    new CustomAgentExecutor(agent)
  );

  const app = express();
  app.use(express.json());

  app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: requestHandler }));

  const securityMiddleware = createSecurityMiddleware(securityPolicy);
  app.use("/a2a/jsonrpc", securityMiddleware, jsonRpcHandler({ requestHandler, userBuilder: buildUser }));
  app.use("/a2a/rest", securityMiddleware, restHandler({ requestHandler, userBuilder: buildUser }));

  app.get("/health", (_request, response) => {
    response.json({
      ok: true,
      agent: agent.id,
      capabilities: Object.keys(securityPolicy.capabilityPolicies),
      cardUrl: `${config.baseUrl}/${AGENT_CARD_PATH}`
    });
  });

  return app;
}
