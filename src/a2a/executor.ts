import { AGENT_CARD_PATH, type AgentCard, type Message } from "@a2a-js/sdk";
import type { AgentExecutor, ExecutionEventBus, RequestContext, User } from "@a2a-js/sdk/server";
import type { CustomAgent } from "../core/agent.js";
import type { SecurityPolicy } from "../security/policy.js";
import { A2A_PROTOCOL_VERSION, PACKAGE_VERSION } from "../version.js";

type ExtendedAgentSkill = AgentCard["skills"][number] & {
  "x-required-scopes"?: string[];
  "x-required-trust-tier"?: string;
  "x-risk-level"?: string;
  "x-approval-required"?: boolean;
  "x-tool-access"?: string;
  "x-allowed-tools"?: string[];
  "x-allowed-principals"?: string[];
  "x-security-metadata"?: Record<string, string | boolean | string[]>;
};

type ExtendedAgentCard = AgentCard & {
  "x-security-requirements"?: SecurityPolicy["securityRequirements"];
  "x-capability-resolution"?: {
    header: string;
    metadataKey: string;
  };
  "x-security-metadata"?: Record<string, string | boolean | string[]>;
};

function getTextFromMessage(message: Message): string {
  return message.parts
    .filter((part): part is Extract<typeof part, { kind: "text" }> => part.kind === "text")
    .map((part) => part.text)
    .join("\n")
    .trim();
}

function getCallerId(user: User | undefined): string {
  if (!user?.isAuthenticated) {
    return "anonymous";
  }

  return user.userName;
}

export function createAgentCard(baseUrl: string, agent: CustomAgent, policy: SecurityPolicy): AgentCard {
  const skills: ExtendedAgentSkill[] = agent.capabilities.map((capability) => {
    const capabilityPolicy = policy.capabilityPolicies[capability.id];

    return {
      id: capability.id,
      name: capability.name,
      description: capability.description,
      tags: capabilityPolicy?.tags ?? [capability.id],
      examples: capabilityPolicy?.examples,
      security: policy.securityRequirements,
      "x-required-scopes": capabilityPolicy?.requiredScopes ?? [],
      "x-required-trust-tier": capabilityPolicy?.requiredTrustTier,
      "x-risk-level": capabilityPolicy?.riskLevel,
      "x-approval-required": capabilityPolicy?.approvalRequired,
      "x-tool-access": capabilityPolicy?.toolAccess,
      "x-allowed-tools": capabilityPolicy?.allowedToolIds,
      "x-allowed-principals": capabilityPolicy?.allowedPrincipals,
      "x-security-metadata": capabilityPolicy?.metadata
    };
  });

  const card: ExtendedAgentCard = {
    name: agent.name,
    description: agent.description,
    protocolVersion: A2A_PROTOCOL_VERSION,
    version: agent.version ?? PACKAGE_VERSION,
    url: `${baseUrl}/a2a/jsonrpc`,
    preferredTransport: "JSONRPC",
    defaultInputModes: ["text"],
    defaultOutputModes: ["text"],
    capabilities: {
      pushNotifications: false
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
    ],
    "x-security-requirements": policy.securityRequirements,
    "x-capability-resolution": {
      header: policy.metadata.capabilityHeader,
      metadataKey: policy.metadata.capabilityMetadataKey
    },
    "x-security-metadata": {
      "x-audience": policy.metadata.audience,
      "x-trust-tier": policy.metadata.trustTier,
      "x-request-id-header": policy.metadata.requestIdHeader,
      "x-approval-header": policy.metadata.approvalHeader
    }
  };

  return card;
}

export class CustomAgentExecutor implements AgentExecutor {
  constructor(private readonly agent: CustomAgent) {}

  async execute(requestContext: RequestContext, eventBus: ExecutionEventBus): Promise<void> {
    const input = getTextFromMessage(requestContext.userMessage);
    const callerId = getCallerId(requestContext.context?.user);

    const result = await this.agent.run(
      {
        taskId: requestContext.taskId,
        message: input,
        capability: requestContext.userMessage.metadata?.capability as string | undefined
      },
      {
        callerId,
        requestId: requestContext.userMessage.metadata?.requestId as string ?? crypto.randomUUID()
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
