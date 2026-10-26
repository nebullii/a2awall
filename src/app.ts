import express, { type Request } from "express";
import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  type AgentExecutor,
  type User
} from "@a2a-js/sdk/server";
import { agentCardHandler, jsonRpcHandler, restHandler } from "@a2a-js/sdk/server/express";
import {
  AGENT_CARD_PATH,
  CustomAgentExecutor,
  GatewayPrincipal,
  createAgentCard
} from "./a2a/executor.js";
import { type CustomAgent } from "./core/agent.js";
import { createExampleAgent } from "./core/example-agent.js";
import {
  createSecurityMiddleware,
  type AuditLogger,
  type SecurityMiddlewareOptions
} from "./security/middleware.js";
import type { IdentityResolver } from "./security/admission.js";
import { TaskOwnershipRegistry, createOwnershipScopedTaskStore } from "./security/tasks.js";
import {
  defaultSecurityPolicy,
  validateSecurityPolicy,
  type SecurityPolicy
} from "./security/policy.js";

export interface AppConfig {
  baseUrl: string;
  agent?: CustomAgent;
  securityPolicy?: SecurityPolicy;
  identityResolver?: IdentityResolver;
  auditLogger?: AuditLogger;
  /**
   * Hard cap on the raw request body, applied before authentication. The
   * per-capability `maxMessageCharacters` limit is enforced after the body has
   * been parsed, so an outer byte limit is what stops an unauthenticated caller
   * from making the gateway parse an arbitrarily large document.
   */
  maxRequestBodyBytes?: number;
  /** Skips startup policy validation. Intended for tests of invalid policies. */
  skipPolicyValidation?: boolean;
  /**
   * Records which principal created each task, so that task-scoped methods can
   * be authorized by ownership. A fresh in-process registry is created when this
   * is omitted; a multi-instance deployment must supply a shared one.
   */
  taskOwnership?: TaskOwnershipRegistry;
  /**
   * Replaces the default executor. The replacement is still reached only after
   * admission, and must take the caller's capability from the authenticated
   * principal rather than from message metadata.
   */
  executor?: AgentExecutor;
}

const DEFAULT_MAX_REQUEST_BODY_BYTES = 256 * 1024;

export function createApp(config: AppConfig) {
  const securityPolicy = config.securityPolicy ?? defaultSecurityPolicy;
  if (!config.skipPolicyValidation) {
    validateSecurityPolicy(securityPolicy);
  }

  const agent = config.agent ?? createExampleAgent(securityPolicy);
  const agentCard = createAgentCard(config.baseUrl, agent, securityPolicy);
  const taskOwnership = config.taskOwnership ?? new TaskOwnershipRegistry();
  const requestHandler = new DefaultRequestHandler(
    agentCard,
    createOwnershipScopedTaskStore(new InMemoryTaskStore(), taskOwnership),
    config.executor ?? new CustomAgentExecutor(agent)
  );

  /**
   * Builds the principal from headers the security middleware has already
   * overwritten with the admission decision, so the executor receives the
   * authorised capability rather than anything the caller supplied.
   */
  async function buildUser(request: Request): Promise<User> {
    const callerId = request.header("x-caller-id");
    const requestId = request.header(securityPolicy.metadata.requestIdHeader);

    if (!callerId || !requestId) {
      throw new Error(
        "Request reached the A2A handler without a gateway admission decision. The security middleware must run first."
      );
    }

    // Absent for methods authorized by authentication or task ownership rather
    // than by a capability. Those never reach the agent executor.
    const capability = request.header(securityPolicy.metadata.capabilityHeader);

    return new GatewayPrincipal(callerId, capability, requestId);
  }

  const app = express();
  app.use(
    express.json({
      limit: config.maxRequestBodyBytes ?? DEFAULT_MAX_REQUEST_BODY_BYTES
    })
  );

  app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: requestHandler }));

  const middlewareOptions: SecurityMiddlewareOptions = {
    identityResolver: config.identityResolver,
    auditLogger: config.auditLogger,
    taskOwnership
  };
  const securityMiddleware = createSecurityMiddleware(securityPolicy, middlewareOptions);

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
