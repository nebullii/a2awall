import type { RiskLevel } from "../security/policy.js";

export interface EvidenceReference {
  source: string;
  quote?: string;
}

export interface ActionProposal {
  actionType: string;
  summary: string;
  riskLevel: RiskLevel;
  requiresApproval: boolean;
  evidence: EvidenceReference[];
}

export interface OutputValidationPolicy {
  requireEvidenceForRiskLevels: RiskLevel[];
  maxSummaryCharacters: number;
}

export interface OutputValidationDecision {
  valid: boolean;
  reasons: string[];
}

export function validateActionProposal(
  proposal: ActionProposal,
  policy: OutputValidationPolicy
): OutputValidationDecision {
  if (!proposal.summary.trim()) {
    return {
      valid: false,
      reasons: ["missing_summary"]
    };
  }

  if (proposal.summary.length > policy.maxSummaryCharacters) {
    return {
      valid: false,
      reasons: ["summary_too_large"]
    };
  }

  if (
    policy.requireEvidenceForRiskLevels.includes(proposal.riskLevel) &&
    proposal.evidence.length === 0
  ) {
    return {
      valid: false,
      reasons: ["missing_evidence"]
    };
  }

  if (proposal.riskLevel === "critical" && !proposal.requiresApproval) {
    return {
      valid: false,
      reasons: ["critical_action_requires_approval"]
    };
  }

  return {
    valid: true,
    reasons: ["output_valid"]
  };
}
