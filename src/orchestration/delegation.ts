import type { RiskLevel, TrustTier } from "../security/policy.js";

export interface DelegationPolicy {
  maxDepth: number;
  maxFanOut: number;
  allowedCapabilities: string[];
  minimumTrustTier: TrustTier;
}

export interface DelegationRequest {
  fromAgentId: string;
  toAgentId: string;
  capability: string;
  depth: number;
  fanOut: number;
  callerTrustTier: TrustTier;
  riskLevel: RiskLevel;
}

export interface DelegationDecision {
  allowed: boolean;
  reasons: string[];
  statusCode?: number;
  message?: string;
}

const TRUST_TIER_ORDER: TrustTier[] = ["public", "partner", "internal", "privileged"];

export function evaluateDelegation(
  request: DelegationRequest,
  policy: DelegationPolicy
): DelegationDecision {
  if (request.depth > policy.maxDepth) {
    return {
      allowed: false,
      reasons: ["max_depth_exceeded"],
      statusCode: 403,
      message: "Delegation depth exceeded."
    };
  }

  if (request.fanOut > policy.maxFanOut) {
    return {
      allowed: false,
      reasons: ["max_fanout_exceeded"],
      statusCode: 403,
      message: "Delegation fan-out exceeded."
    };
  }

  if (!policy.allowedCapabilities.includes(request.capability)) {
    return {
      allowed: false,
      reasons: ["capability_not_delegable"],
      statusCode: 403,
      message: `Capability '${request.capability}' is not delegable.`
    };
  }

  if (
    TRUST_TIER_ORDER.indexOf(request.callerTrustTier) <
    TRUST_TIER_ORDER.indexOf(policy.minimumTrustTier)
  ) {
    return {
      allowed: false,
      reasons: ["delegation_trust_tier_too_low"],
      statusCode: 403,
      message: "Caller trust tier is too low for delegation."
    };
  }

  if (request.riskLevel === "critical" && request.depth > 0) {
    return {
      allowed: false,
      reasons: ["critical_risk_no_transitive_delegation"],
      statusCode: 403,
      message: "Critical-risk work cannot be transitively delegated."
    };
  }

  return {
    allowed: true,
    reasons: ["delegation_admitted"]
  };
}
