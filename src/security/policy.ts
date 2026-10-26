import { createHash } from "node:crypto";

export interface SecuritySchemeDefinition {
  type: "http";
  scheme: "bearer";
  bearerFormat?: string;
  description?: string;
}

export type TrustTier = "public" | "partner" | "internal" | "privileged";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type ToolAccessMode = "none" | "read-only" | "bounded-write" | "privileged";

export const TRUST_TIERS: readonly TrustTier[] = ["public", "partner", "internal", "privileged"];
export const RISK_LEVELS: readonly RiskLevel[] = ["low", "medium", "high", "critical"];

/** Thrown for any policy that cannot be enforced as written. Never recoverable. */
export class PolicyConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyConfigurationError";
  }
}

/** The development fixture credential. Rejected outside development. */
export const DEVELOPMENT_TOKEN = "dev-token";

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function compareTrustTiers(left: TrustTier, right: TrustTier): number {
  return TRUST_TIERS.indexOf(left) - TRUST_TIERS.indexOf(right);
}

export function trustTierSatisfies(actual: TrustTier, required: TrustTier | undefined): boolean {
  if (!required) {
    return true;
  }

  return compareTrustTiers(actual, required) >= 0;
}

export interface SecurityIdentity {
  /**
   * Plaintext credential. Supported for development only; policy validation
   * rejects it when NODE_ENV is production. Prefer `tokenSha256`.
   */
  token?: string;
  /** Lowercase hex SHA-256 digest of the bearer credential. */
  tokenSha256?: string;
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
  /**
   * Informational. Declares who this deployment is intended for and is
   * published on the Agent Card. It is not an enforced control: a static bearer
   * token carries no audience claim. Audience is only enforceable when identity
   * resolution validates a token with an `aud` claim.
   */
  audience: string;
  trustTier: string;
  capabilityHeader: string;
  capabilityMetadataKey: string;
  requestIdHeader: string;
  approvalHeader: string;
}

export interface ApprovalPolicy {
  /**
   * Lowercase hex SHA-256 digests of the accepted approval tokens. Required
   * whenever any capability sets `approvalRequired`, so that the approval gate
   * verifies a credential instead of merely observing that a header is present.
   */
  tokenSha256: string[];
}

export interface SecurityPolicy {
  securitySchemes: Record<string, SecuritySchemeDefinition>;
  securityRequirements: Array<Record<string, string[]>>;
  identities: SecurityIdentity[];
  capabilityPolicies: Record<string, CapabilityPolicy>;
  metadata: SecurityPolicyMetadata;
  approval?: ApprovalPolicy;
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
      token: DEVELOPMENT_TOKEN,
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

export interface ValidateSecurityPolicyOptions {
  /** Defaults to process.env.NODE_ENV. */
  nodeEnv?: string;
}

/**
 * Rejects policies that cannot be enforced as written. Called by `createApp`, so
 * a contradictory or fail-open policy stops the process at startup rather than
 * silently admitting traffic.
 */
export function validateSecurityPolicy(
  policy: SecurityPolicy,
  options: ValidateSecurityPolicyOptions = {}
): SecurityPolicy {
  const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV;
  const isProduction = nodeEnv === "production";
  const capabilityNames = Object.keys(policy.capabilityPolicies);

  if (capabilityNames.length === 0) {
    throw new PolicyConfigurationError("Security policy declares no capabilities.");
  }

  if (policy.identities.length === 0) {
    throw new PolicyConfigurationError(
      "Security policy declares no identities, so every request would be rejected."
    );
  }

  const seenPrincipals = new Set<string>();
  for (const identity of policy.identities) {
    if (!identity.principalId) {
      throw new PolicyConfigurationError("Every identity must declare a principalId.");
    }

    if (seenPrincipals.has(identity.principalId)) {
      throw new PolicyConfigurationError(`Duplicate principalId '${identity.principalId}'.`);
    }
    seenPrincipals.add(identity.principalId);

    if (!identity.token && !identity.tokenSha256) {
      throw new PolicyConfigurationError(
        `Identity '${identity.principalId}' declares neither token nor tokenSha256.`
      );
    }

    if (identity.tokenSha256 && !/^[0-9a-f]{64}$/.test(identity.tokenSha256)) {
      throw new PolicyConfigurationError(
        `Identity '${identity.principalId}' has a tokenSha256 that is not a lowercase hex SHA-256 digest.`
      );
    }

    if (!TRUST_TIERS.includes(identity.trustTier)) {
      throw new PolicyConfigurationError(
        `Identity '${identity.principalId}' has unknown trust tier '${identity.trustTier}'. Known tiers: ${TRUST_TIERS.join(", ")}.`
      );
    }

    if (identity.token === DEVELOPMENT_TOKEN && isProduction) {
      throw new PolicyConfigurationError(
        `Identity '${identity.principalId}' uses the built-in development token in production. Set SECURITY_BEARER_TOKEN, or supply tokenSha256.`
      );
    }

    if (identity.token && isProduction) {
      throw new PolicyConfigurationError(
        `Identity '${identity.principalId}' stores a plaintext token in production. Use tokenSha256 instead.`
      );
    }

    for (const capability of identity.allowedCapabilities ?? []) {
      if (!policy.capabilityPolicies[capability]) {
        throw new PolicyConfigurationError(
          `Identity '${identity.principalId}' is granted unknown capability '${capability}'. Known capabilities: ${capabilityNames.join(", ")}.`
        );
      }
    }
  }

  for (const [name, capabilityPolicy] of Object.entries(policy.capabilityPolicies)) {
    const label = `Capability '${name}'`;

    if (capabilityPolicy.requiredScopes.length === 0) {
      throw new PolicyConfigurationError(
        `${label} declares no required scopes. Declare at least one scope so the grant is explicit.`
      );
    }

    if (
      capabilityPolicy.requiredTrustTier &&
      !TRUST_TIERS.includes(capabilityPolicy.requiredTrustTier)
    ) {
      throw new PolicyConfigurationError(
        `${label} requires unknown trust tier '${capabilityPolicy.requiredTrustTier}'.`
      );
    }

    if (!RISK_LEVELS.includes(capabilityPolicy.riskLevel)) {
      throw new PolicyConfigurationError(
        `${label} has unknown risk level '${capabilityPolicy.riskLevel}'.`
      );
    }

    if (capabilityPolicy.riskLevel === "critical" && !capabilityPolicy.approvalRequired) {
      throw new PolicyConfigurationError(
        `${label} is critical risk but does not require approval. Output validation would reject every action it proposes.`
      );
    }

    if (capabilityPolicy.toolAccess === "none") {
      if (capabilityPolicy.allowedToolIds.length > 0) {
        throw new PolicyConfigurationError(
          `${label} has toolAccess 'none' but lists allowed tools. Remove the tools or raise the access mode.`
        );
      }

      if (capabilityPolicy.maxToolCalls > 0) {
        throw new PolicyConfigurationError(
          `${label} has toolAccess 'none' but a non-zero tool call budget.`
        );
      }
    } else {
      if (capabilityPolicy.allowedToolIds.length === 0) {
        throw new PolicyConfigurationError(
          `${label} grants '${capabilityPolicy.toolAccess}' tool access but lists no allowed tools.`
        );
      }

      if (capabilityPolicy.maxToolCalls <= 0) {
        throw new PolicyConfigurationError(
          `${label} grants tool access but has a tool call budget of ${capabilityPolicy.maxToolCalls}.`
        );
      }
    }

    if (capabilityPolicy.maxRuntimeMs <= 0) {
      throw new PolicyConfigurationError(`${label} has a non-positive maxRuntimeMs.`);
    }

    if (capabilityPolicy.maxMessageCharacters <= 0) {
      throw new PolicyConfigurationError(`${label} has a non-positive maxMessageCharacters.`);
    }

    if (capabilityPolicy.allowedPrincipals?.length === 0) {
      throw new PolicyConfigurationError(
        `${label} has an empty allowedPrincipals list, which denies every caller. Remove the field to allow all principals.`
      );
    }
  }

  const capabilitiesRequiringApproval = Object.entries(policy.capabilityPolicies)
    .filter(([, capabilityPolicy]) => capabilityPolicy.approvalRequired)
    .map(([name]) => name);

  if (capabilitiesRequiringApproval.length > 0) {
    const approvalDigests = policy.approval?.tokenSha256 ?? [];
    if (approvalDigests.length === 0) {
      throw new PolicyConfigurationError(
        `Capabilities require approval (${capabilitiesRequiringApproval.join(", ")}) but no approval tokens are configured. ` +
          "Set policy.approval.tokenSha256, otherwise the approval gate would accept any value in the approval header."
      );
    }

    for (const digest of approvalDigests) {
      if (!/^[0-9a-f]{64}$/.test(digest)) {
        throw new PolicyConfigurationError(
          "policy.approval.tokenSha256 entries must be lowercase hex SHA-256 digests."
        );
      }
    }
  }

  if (Object.keys(policy.securitySchemes).length === 0) {
    throw new PolicyConfigurationError("Security policy declares no security schemes.");
  }

  if (policy.securityRequirements.length === 0) {
    throw new PolicyConfigurationError(
      "Security policy declares no security requirements, so the Agent Card would advertise an unauthenticated agent."
    );
  }

  const { capabilityHeader, capabilityMetadataKey, requestIdHeader, approvalHeader } =
    policy.metadata;
  for (const [field, value] of Object.entries({
    capabilityHeader,
    capabilityMetadataKey,
    requestIdHeader,
    approvalHeader
  })) {
    if (!value) {
      throw new PolicyConfigurationError(`Security policy metadata is missing '${field}'.`);
    }
  }

  return policy;
}

export interface SecurityPolicyEnvironment {
  bearerToken?: string;
  bearerTokenSha256?: string;
  principalId?: string;
  scopes?: string;
  allowedCapabilities?: string;
  audience?: string;
  trustTier?: string;
  identityTrustTier?: TrustTier;
}

/**
 * Parses a trust tier, throwing on anything unrecognised. A typo must not fall
 * back to a more privileged default.
 */
function parseTrustTier(value: string | undefined, field: string): TrustTier | undefined {
  if (value === undefined || value === "") {
    return undefined;
  }

  if (!TRUST_TIERS.includes(value as TrustTier)) {
    throw new PolicyConfigurationError(
      `${field} has unknown trust tier '${value}'. Known tiers: ${TRUST_TIERS.join(", ")}.`
    );
  }

  return value as TrustTier;
}

function parseCsv(value: string | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }

  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/**
 * Builds a policy from environment variables for the single-identity case.
 *
 * This path can only select from capability policies that already exist in
 * `defaultSecurityPolicy`; it cannot define new ones. Naming a capability that
 * has no policy is an error rather than an implicit grant, and scopes are never
 * derived from the capability list, because a grant derived from its own
 * requirement makes the scope check vacuous.
 *
 * Define new capabilities by constructing a `SecurityPolicy` in code and passing
 * it to `createApp`.
 */
export function createSecurityPolicyFromEnv(
  environment: SecurityPolicyEnvironment = process.env
): SecurityPolicy {
  const requestedCapabilities = parseCsv(environment.allowedCapabilities);
  const knownCapabilities = Object.keys(defaultSecurityPolicy.capabilityPolicies);

  if (requestedCapabilities?.length === 0) {
    throw new PolicyConfigurationError(
      "SECURITY_ALLOWED_CAPABILITIES is set but empty. Remove it or name at least one capability."
    );
  }

  const allowedCapabilities = requestedCapabilities ?? knownCapabilities;

  const unknownCapabilities = allowedCapabilities.filter(
    (capability) => !defaultSecurityPolicy.capabilityPolicies[capability]
  );
  if (unknownCapabilities.length > 0) {
    throw new PolicyConfigurationError(
      `SECURITY_ALLOWED_CAPABILITIES names capabilities with no policy: ${unknownCapabilities.join(", ")}. ` +
        `Known capabilities: ${knownCapabilities.join(", ")}. ` +
        "Define new capabilities by building a SecurityPolicy in code, not through the environment."
    );
  }

  const configuredScopes = parseCsv(environment.scopes);
  if (requestedCapabilities && !configuredScopes?.length) {
    throw new PolicyConfigurationError(
      "SECURITY_ALLOWED_CAPABILITIES is set but SECURITY_SCOPES is not. Scopes must be granted explicitly; " +
        "they are never derived from the capability list."
    );
  }

  const scopes = configuredScopes ?? defaultSecurityPolicy.identities[0]?.scopes ?? [];
  if (scopes.length === 0) {
    throw new PolicyConfigurationError("SECURITY_SCOPES resolved to an empty scope set.");
  }

  const capabilityPolicies = Object.fromEntries(
    allowedCapabilities.map((capability) => [
      capability,
      defaultSecurityPolicy.capabilityPolicies[capability]!
    ])
  );

  const bearerToken = environment.bearerToken;
  const bearerTokenSha256 = environment.bearerTokenSha256;
  if (bearerToken && bearerTokenSha256) {
    throw new PolicyConfigurationError(
      "Set either SECURITY_BEARER_TOKEN or SECURITY_BEARER_TOKEN_SHA256, not both."
    );
  }

  const principalId =
    environment.principalId ?? defaultSecurityPolicy.identities[0]?.principalId ?? "secured-caller";

  const identity: SecurityIdentity = {
    principalId,
    scopes,
    trustTier:
      environment.identityTrustTier ??
      parseTrustTier(environment.trustTier, "SECURITY_TRUST_TIER") ??
      defaultSecurityPolicy.identities[0]?.trustTier ??
      "public",
    allowedCapabilities,
    metadata: {
      environment: "configured"
    }
  };

  if (bearerTokenSha256) {
    identity.tokenSha256 = bearerTokenSha256.trim().toLowerCase();
  } else {
    identity.token = bearerToken ?? defaultSecurityPolicy.identities[0]?.token ?? DEVELOPMENT_TOKEN;
  }

  return {
    securitySchemes: defaultSecurityPolicy.securitySchemes,
    securityRequirements: defaultSecurityPolicy.securityRequirements,
    identities: [identity],
    capabilityPolicies,
    metadata: {
      ...defaultSecurityPolicy.metadata,
      audience: environment.audience ?? defaultSecurityPolicy.metadata.audience,
      trustTier: environment.trustTier ?? defaultSecurityPolicy.metadata.trustTier
    }
  };
}
