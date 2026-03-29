export interface SecuritySchemeDefinition {
  type: "http";
  scheme: "bearer";
  bearerFormat?: string;
  description?: string;
}

export type TrustTier = "public" | "partner" | "internal" | "privileged";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type ToolAccessMode = "none" | "read-only" | "bounded-write" | "privileged";

export interface SecurityIdentity {
  token: string;
  principalId: string;
  scopes: string[];
  trustTier: TrustTier;
  allowedCapabilities?: string[];
  metadata?: Record<string, string>;
}

export interface CapabilityPolicy {
  name: string;
  description: string;
  tags?: string[];
  examples?: string[];
  requiredScopes: string[];
  requiredTrustTier?: TrustTier;
  riskLevel: RiskLevel;
  approvalRequired: boolean;
  toolAccess: ToolAccessMode;
  allowedToolIds: string[];
  maxToolCalls: number;
  maxRuntimeMs: number;
  networkDomains?: string[];
  filesystemPrefixes?: string[];
  maxMessageCharacters: number;
  allowedPrincipals?: string[];
  metadata?: Record<string, string | boolean | string[]>;
}

export interface SecurityPolicyMetadata {
  audience: string;
  trustTier: string;
  capabilityHeader: string;
  capabilityMetadataKey: string;
  requestIdHeader: string;
  approvalHeader: string;
}

export interface SecurityPolicy {
  securitySchemes: Record<string, SecuritySchemeDefinition>;
  securityRequirements: Array<Record<string, string[]>>;
  identities: SecurityIdentity[];
  capabilityPolicies: Record<string, CapabilityPolicy>;
  metadata: SecurityPolicyMetadata;
}

export const defaultSecurityPolicy: SecurityPolicy = {
  securitySchemes: {
    bearerAuth: {
      type: "http",
      scheme: "bearer",
      bearerFormat: "opaque-token",
      description: "Bearer token with capability scopes."
    }
  },
  securityRequirements: [{ bearerAuth: [] }],
  identities: [
    {
      token: "dev-token",
      principalId: "secured-caller",
      scopes: ["agent:invoke", "agent:echo", "agent:template-echo"],
      trustTier: "internal",
      allowedCapabilities: ["echo", "template-echo"],
      metadata: {
        environment: "development"
      }
    }
  ],
  capabilityPolicies: {
    echo: {
      name: "Echo",
      description: "Returns the caller's message with minimal transformation.",
      tags: ["echo"],
      examples: ["Echo 'hello world' back to me."],
      requiredScopes: ["agent:echo"],
      requiredTrustTier: "public",
      riskLevel: "low",
      approvalRequired: false,
      toolAccess: "none",
      allowedToolIds: [],
      maxToolCalls: 0,
      maxRuntimeMs: 1000,
      maxMessageCharacters: 4000,
      metadata: {
        "x-trust-tier": "internal",
        "x-audience": "trusted-a2a-clients"
      }
    },
    "template-echo": {
      name: "Template Echo",
      description: "Formats the caller's message through the secure tool runtime.",
      tags: ["template-echo", "tool-runtime"],
      examples: ["Format 'hello world' with the secure template tool."],
      requiredScopes: ["agent:template-echo"],
      requiredTrustTier: "public",
      riskLevel: "low",
      approvalRequired: false,
      toolAccess: "read-only",
      allowedToolIds: ["template-render"],
      maxToolCalls: 1,
      maxRuntimeMs: 1000,
      maxMessageCharacters: 4000,
      metadata: {
        "x-trust-tier": "internal",
        "x-audience": "trusted-a2a-clients"
      }
    }
  },
  metadata: {
    audience: "trusted-a2a-clients",
    trustTier: "internal",
    capabilityHeader: "x-agent-capability",
    capabilityMetadataKey: "capability",
    requestIdHeader: "x-request-id",
    approvalHeader: "x-approval-token"
  }
};

export interface SecurityPolicyEnvironment {
  bearerToken?: string;
  principalId?: string;
  scopes?: string;
  allowedCapabilities?: string;
  audience?: string;
  trustTier?: string;
  identityTrustTier?: TrustTier;
}

function parseTrustTier(value: string | undefined): TrustTier | undefined {
  if (value === "public" || value === "partner" || value === "internal" || value === "privileged") {
    return value;
  }

  return undefined;
}

function parseCsv(value: string | undefined, fallback: string[]): string[] {
  if (!value) {
    return fallback;
  }

  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function createSecurityPolicyFromEnv(
  environment: SecurityPolicyEnvironment = process.env
): SecurityPolicy {
  const bearerToken = environment.bearerToken ?? defaultSecurityPolicy.identities[0]?.token ?? "dev-token";
  const principalId =
    environment.principalId ?? defaultSecurityPolicy.identities[0]?.principalId ?? "secured-caller";
  const allowedCapabilities = parseCsv(
    environment.allowedCapabilities,
    Object.keys(defaultSecurityPolicy.capabilityPolicies)
  );
  const scopes = parseCsv(environment.scopes, ["agent:invoke", ...allowedCapabilities.map((capability) => `agent:${capability}`)]);

  const capabilityPolicies = Object.fromEntries(
    allowedCapabilities.map((capability) => {
      const existing = defaultSecurityPolicy.capabilityPolicies[capability];
      const capabilityPolicy: CapabilityPolicy = existing ?? {
        name: capability,
        description: `Capability policy for ${capability}.`,
        tags: [capability],
        requiredScopes: [`agent:${capability}`],
        requiredTrustTier: "public",
        riskLevel: "medium",
        approvalRequired: false,
        toolAccess: "none",
        allowedToolIds: [],
        maxToolCalls: 0,
        maxRuntimeMs: 1000,
        maxMessageCharacters: 4000,
        metadata: {
          "x-trust-tier": environment.trustTier ?? defaultSecurityPolicy.metadata.trustTier,
          "x-audience": environment.audience ?? defaultSecurityPolicy.metadata.audience
        }
      };

      return [
        capability,
        {
          ...capabilityPolicy,
          requiredScopes:
            capabilityPolicy.requiredScopes.length > 0
              ? capabilityPolicy.requiredScopes
              : [`agent:${capability}`]
        }
      ];
    })
  );

  return {
    securitySchemes: defaultSecurityPolicy.securitySchemes,
    securityRequirements: defaultSecurityPolicy.securityRequirements,
    identities: [
      {
        token: bearerToken,
        principalId,
        scopes,
        trustTier:
          environment.identityTrustTier ??
          parseTrustTier(environment.trustTier) ??
          defaultSecurityPolicy.identities[0]?.trustTier ??
          "internal",
        allowedCapabilities,
        metadata: {
          environment: "configured"
        }
      }
    ],
    capabilityPolicies,
    metadata: {
      ...defaultSecurityPolicy.metadata,
      audience: environment.audience ?? defaultSecurityPolicy.metadata.audience,
      trustTier: environment.trustTier ?? defaultSecurityPolicy.metadata.trustTier
    }
  };
}
