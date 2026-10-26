import { AGENT_CARD_PATH, type AgentCard, type AgentCardSignature, type Message } from "@a2a-js/sdk";
import type { AgentExecutor, ExecutionEventBus, RequestContext, User } from "@a2a-js/sdk/server";
import type { CustomAgent } from "../core/agent.js";
import type { SecurityPolicy } from "../security/policy.js";
import { A2A_PROTOCOL_VERSION, PACKAGE_VERSION } from "../version.js";

/**
 * Identifies the A2AWall security extension on the Agent Card. A2A declares
 * vendor behaviour through URI-identified extensions in
 * `capabilities.extensions`; ad-hoc `x-` properties are not part of the
 * AgentCard schema and would not survive card canonicalisation for signing.
 */
export const A2AWALL_SECURITY_EXTENSION_URI =
  "https://nebullii.github.io/a2awall/extensions/security-policy/v1";

/**
 * The authenticated caller, as established by the gateway middleware. The
 * capability is carried here rather than read from message metadata: metadata
 * is caller-controlled, so reading it at execution time would let a caller be
 * admitted under one capability and executed under another.
 */
export class GatewayPrincipal implements User {
  constructor(
    readonly userName: string,
    /**
     * Absent for requests authorized by task ownership or by authentication
     * alone, which never reach the agent executor.
     */
    readonly capability: string | undefined,
    readonly requestId: string,
    readonly trustTier?: string
  ) {}

  get isAuthenticated(): boolean {
    return true;
  }
}

export function isGatewayPrincipal(user: unknown): user is GatewayPrincipal {
  return user instanceof GatewayPrincipal;
}

/**
 * Extracts text by the presence of the payload rather than by the `kind`
 * discriminator. The REST binding decodes messages from proto-JSON, where parts
 * carry no `kind`, so a discriminator-based filter reads every REST message as
 * empty. A2A 1.0 drops `kind` from the wire format entirely.
 */
function getTextFromMessage(message: Message): string {
  return message.parts
    .filter((part): part is Extract<typeof part, { kind: "text" }> =>
      typeof (part as { text?: unknown }).text === "string"
    )
    .map((part) => part.text)
    .join("\n")
    .trim();
}

export interface CreateAgentCardOptions {
  /**
   * Produces JWS signatures for the card. A2A specifies canonicalisation and
   * JWS requirements for signed cards; A2AWall does not ship a signer, because
   * an incorrectly canonicalised signature is worse than an unsigned card.
   * Supply a compliant signer here to publish a signed card.
   */
  signatures?: AgentCardSignature[];
}

export function createAgentCard(
  baseUrl: string,
  agent: CustomAgent,
  policy: SecurityPolicy,
  options: CreateAgentCardOptions = {}
): AgentCard {
  const skills = agent.capabilities.map((capability) => {
    const capabilityPolicy = policy.capabilityPolicies[capability.id];

    return {
      id: capability.id,
      name: capability.name,
      description: capability.description,
      tags: capabilityPolicy?.tags ?? [capability.id],
      examples: capabilityPolicy?.examples,
      security: policy.securityRequirements
    };
  });

  // Published per skill. `allowedPrincipals` is deliberately omitted: the
  // public card is unauthenticated, and an allowlist of caller identities is
  // reconnaissance rather than something a client needs in order to call.
  const capabilityParams = Object.fromEntries(
    agent.capabilities
      .map((capability) => [capability.id, policy.capabilityPolicies[capability.id]] as const)
      .filter(([, capabilityPolicy]) => capabilityPolicy !== undefined)
      .map(([id, capabilityPolicy]) => [
        id,
        {
          requiredScopes: capabilityPolicy!.requiredScopes,
          requiredTrustTier: capabilityPolicy!.requiredTrustTier,
          riskLevel: capabilityPolicy!.riskLevel,
          approvalRequired: capabilityPolicy!.approvalRequired,
          toolAccess: capabilityPolicy!.toolAccess,
          allowedToolIds: capabilityPolicy!.allowedToolIds,
          maxMessageCharacters: capabilityPolicy!.maxMessageCharacters
        }
      ])
  );

  const card: AgentCard = {
    name: agent.name,
    description: agent.description,
    protocolVersion: A2A_PROTOCOL_VERSION,
    version: agent.version ?? PACKAGE_VERSION,
    url: `${baseUrl}/a2a/jsonrpc`,
    preferredTransport: "JSONRPC",
    defaultInputModes: ["text"],
    defaultOutputModes: ["text"],
    capabilities: {
      streaming: false,
      pushNotifications: false,
      stateTransitionHistory: false,
      extensions: [
        {
          uri: A2AWALL_SECURITY_EXTENSION_URI,
          description:
            "Declares the gateway admission policy applied to each skill: required scopes, trust tier, risk level, approval requirement and tool access.",
          // Advisory. The gateway enforces this policy server-side whether or
          // not the client activates the extension, so requiring activation
          // would break plain A2A clients for no security benefit.
          required: false,
          params: {
            audience: policy.metadata.audience,
            trustTier: policy.metadata.trustTier,
            capabilityResolution: {
              header: policy.metadata.capabilityHeader,
              metadataKey: policy.metadata.capabilityMetadataKey
            },
            requestIdHeader: policy.metadata.requestIdHeader,
            approvalHeader: policy.metadata.approvalHeader,
            capabilities: capabilityParams
          }
        }
      ]
    },
    securitySchemes: policy.securitySchemes,
    security: policy.securityRequirements,
    skills,
    additionalInterfaces: [
      {
        url: `${baseUrl}/a2a/jsonrpc`,
        transport: "JSONRPC"
      },
      {
        url: `${baseUrl}/a2a/rest`,
        transport: "HTTP+JSON"
      }
    ]
  };

  if (options.signatures?.length) {
    card.signatures = options.signatures;
  }

  return card;
}

export interface CustomAgentExecutorOptions {
  /**
   * When true (the default) the executor refuses to run without an
   * authenticated gateway principal, so that mounting the A2A handlers without
   * the security middleware fails closed instead of running as "anonymous".
   */
  requireAuthenticatedContext?: boolean;
}

export class CustomAgentExecutor implements AgentExecutor {
  private readonly requireAuthenticatedContext: boolean;

  constructor(
    private readonly agent: CustomAgent,
    options: CustomAgentExecutorOptions = {}
  ) {
    this.requireAuthenticatedContext = options.requireAuthenticatedContext ?? true;
  }

  async execute(requestContext: RequestContext, eventBus: ExecutionEventBus): Promise<void> {
    const user = requestContext.context?.user;
    const principal = isGatewayPrincipal(user) ? user : undefined;

    if (!principal && this.requireAuthenticatedContext) {
      throw new Error(
        "Refusing to execute without an authenticated gateway principal. Mount the A2AWall security middleware in front of the A2A handlers, or construct the executor with requireAuthenticatedContext: false."
      );
    }

    const input = getTextFromMessage(requestContext.userMessage);
    const callerId = principal?.userName ?? "anonymous";
    const requestId = principal?.requestId ?? crypto.randomUUID();

    const result = await this.agent.run(
      {
        taskId: requestContext.taskId,
        message: input,
        // Sourced from the admission decision, never from message metadata.
        capability: principal?.capability
      },
      {
        callerId,
        requestId
      }
    );

    const response: Message = {
      kind: "message",
      messageId: crypto.randomUUID(),
      role: "agent",
      contextId: requestContext.contextId,
      taskId: requestContext.taskId,
      parts: [{ kind: "text", text: result.text }]
    };

    eventBus.publish(response);
    eventBus.finished();
  }

  async cancelTask(): Promise<void> {}
}

export { AGENT_CARD_PATH };
