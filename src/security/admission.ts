import type { Request } from "express";
import type {
  CapabilityPolicy,
  RiskLevel,
  SecurityIdentity,
  SecurityPolicy,
  TrustTier
} from "./policy.js";

export interface AdmissionContext {
  capability: string;
  identity: SecurityIdentity;
  capabilityPolicy: CapabilityPolicy;
  requestId: string;
  messageText: string;
}

export interface AdmissionDecision {
  allowed: boolean;
  statusCode?: number;
  errorCode?: string;
  message?: string;
  context?: AdmissionContext;
  reasons: string[];
  riskLevel?: RiskLevel;
}

const TRUST_TIER_ORDER: TrustTier[] = ["public", "partner", "internal", "privileged"];

function getBearerToken(request: Request): string | undefined {
  const authHeader = request.header("authorization");
  if (!authHeader) {
    return undefined;
  }

  const [scheme, ...rest] = authHeader.trim().split(/\s+/);
  if (scheme.toLowerCase() !== "bearer" || rest.length === 0) {
    return undefined;
  }

  return rest.join(" ");
}

function findIdentity(policy: SecurityPolicy, token: string | undefined): SecurityIdentity | undefined {
  if (!token) {
    return undefined;
  }

  return policy.identities.find((identity) => identity.token === token);
}

function getCapabilityFromBody(request: Request, metadataKey: string): string | undefined {
  if (!request.body || typeof request.body !== "object") {
    return undefined;
  }

  const body = request.body as {
    method?: string;
    params?: {
      metadata?: Record<string, unknown>;
      message?: {
        parts?: Array<{ kind?: string; text?: string }>;
        metadata?: Record<string, unknown>;
      };
    };
    metadata?: Record<string, unknown>;
  };

  const candidates = [
    body.metadata?.[metadataKey],
    body.params?.metadata?.[metadataKey],
    body.params?.message?.metadata?.[metadataKey]
  ];

  return candidates.find((value): value is string => typeof value === "string");
}

function getMessageText(request: Request): string {
  if (!request.body || typeof request.body !== "object") {
    return "";
  }

  const body = request.body as {
    params?: {
      message?: {
        parts?: Array<{ kind?: string; text?: string }>;
      };
    };
  };

  return (body.params?.message?.parts ?? [])
    .filter((part): part is { kind: "text"; text: string } => part.kind === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n")
    .trim();
}

function resolveCapability(request: Request, policy: SecurityPolicy): string {
  return (
    request.header(policy.metadata.capabilityHeader) ??
    getCapabilityFromBody(request, policy.metadata.capabilityMetadataKey) ??
    Object.keys(policy.capabilityPolicies)[0] ??
    "default"
  );
}

function trustTierSatisfies(actual: TrustTier, required: TrustTier | undefined): boolean {
  if (!required) {
    return true;
  }

  return TRUST_TIER_ORDER.indexOf(actual) >= TRUST_TIER_ORDER.indexOf(required);
}

export function evaluateAdmission(request: Request, policy: SecurityPolicy): AdmissionDecision {
  const identity = findIdentity(policy, getBearerToken(request));
  if (!identity) {
    return {
      allowed: false,
      statusCode: 401,
      errorCode: "unauthorized",
      message: "Missing or invalid bearer token.",
      reasons: ["missing_identity"]
    };
  }

  const capability = resolveCapability(request, policy);
  const capabilityPolicy = policy.capabilityPolicies[capability];
  if (!capabilityPolicy) {
    return {
      allowed: false,
      statusCode: 403,
      errorCode: "forbidden",
      message: `Capability '${capability}' is not allowed.`,
      reasons: ["unknown_capability"]
    };
  }

  if (identity.allowedCapabilities && !identity.allowedCapabilities.includes(capability)) {
    return {
      allowed: false,
      statusCode: 403,
      errorCode: "forbidden",
      message: `Caller '${identity.principalId}' cannot use capability '${capability}'.`,
      reasons: ["capability_not_granted"],
      riskLevel: capabilityPolicy.riskLevel
    };
  }

  const hasRequiredScopes = capabilityPolicy.requiredScopes.every((scope) =>
    identity.scopes.includes(scope)
  );
  if (!hasRequiredScopes) {
    return {
      allowed: false,
      statusCode: 403,
      errorCode: "forbidden",
      message: `Caller '${identity.principalId}' is missing required scopes for capability '${capability}'.`,
      reasons: ["missing_scope"],
      riskLevel: capabilityPolicy.riskLevel
    };
  }

  if (!trustTierSatisfies(identity.trustTier, capabilityPolicy.requiredTrustTier)) {
    return {
      allowed: false,
      statusCode: 403,
      errorCode: "forbidden",
      message: `Caller '${identity.principalId}' does not meet the trust tier for capability '${capability}'.`,
      reasons: ["insufficient_trust_tier"],
      riskLevel: capabilityPolicy.riskLevel
    };
  }

  if (
    capabilityPolicy.allowedPrincipals &&
    !capabilityPolicy.allowedPrincipals.includes(identity.principalId)
  ) {
    return {
      allowed: false,
      statusCode: 403,
      errorCode: "forbidden",
      message: `Caller '${identity.principalId}' is not allowed to use capability '${capability}'.`,
      reasons: ["principal_not_allowed"],
      riskLevel: capabilityPolicy.riskLevel
    };
  }

  if (capabilityPolicy.approvalRequired && !request.header(policy.metadata.approvalHeader)) {
    return {
      allowed: false,
      statusCode: 403,
      errorCode: "approval_required",
      message: `Capability '${capability}' requires an approval token.`,
      reasons: ["approval_missing"],
      riskLevel: capabilityPolicy.riskLevel
    };
  }

  const messageText = getMessageText(request);
  if (messageText.length > capabilityPolicy.maxMessageCharacters) {
    return {
      allowed: false,
      statusCode: 413,
      errorCode: "payload_too_large",
      message: `Capability '${capability}' exceeded the maximum message size.`,
      reasons: ["message_too_large"],
      riskLevel: capabilityPolicy.riskLevel
    };
  }

  const requestId = request.header(policy.metadata.requestIdHeader) ?? crypto.randomUUID();

  return {
    allowed: true,
    reasons: ["admitted"],
    riskLevel: capabilityPolicy.riskLevel,
    context: {
      capability,
      identity,
      capabilityPolicy,
      requestId,
      messageText
    }
  };
}
