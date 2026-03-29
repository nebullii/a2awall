import {
  createContextEnvelope,
  type ContextEnvelope,
  type ContextEnvelopeInput,
  type ContextSource,
  type TrustLabel
} from "./envelope.js";

export interface ContextBoundaryPolicy {
  instructionSources: ContextSource[];
  overrideSources: ContextSource[];
  writableMemorySources: ContextSource[];
  verifiedSources: ContextSource[];
}

export interface TrustedContextBundle {
  instructionEnvelopes: ContextEnvelope[];
  referenceEnvelopes: ContextEnvelope[];
  blockedEnvelopes: ContextEnvelope[];
  warnings: string[];
}

const INSTRUCTION_OVERRIDE_PATTERNS = [
  /\bignore (all )?(previous|prior|earlier) instructions\b/i,
  /\boverride (the )?(system|developer) instructions\b/i,
  /\bdisregard (the )?(system|developer|policy)\b/i,
  /\byou are now\b/i
];

export const defaultContextBoundaryPolicy: ContextBoundaryPolicy = {
  instructionSources: ["system", "developer"],
  overrideSources: ["system"],
  writableMemorySources: ["system", "developer", "tool"],
  verifiedSources: ["system", "developer", "tool"]
};

function detectInstructionOverrideAttempt(content: string): boolean {
  return INSTRUCTION_OVERRIDE_PATTERNS.some((pattern) => pattern.test(content));
}

function shouldUpgradeTrustLabel(
  source: ContextSource,
  trustLabel: TrustLabel,
  policy: ContextBoundaryPolicy
): TrustLabel {
  if (trustLabel !== "untrusted") {
    return trustLabel;
  }

  return policy.verifiedSources.includes(source) ? "verified" : "untrusted";
}

export function buildTrustedContextBundle(
  inputs: ContextEnvelopeInput[],
  policy: ContextBoundaryPolicy = defaultContextBoundaryPolicy
): TrustedContextBundle {
  const instructionEnvelopes: ContextEnvelope[] = [];
  const referenceEnvelopes: ContextEnvelope[] = [];
  const blockedEnvelopes: ContextEnvelope[] = [];
  const warnings: string[] = [];

  for (const input of inputs) {
    const envelope = createContextEnvelope(input);
    envelope.trustLabel = shouldUpgradeTrustLabel(envelope.source, envelope.trustLabel, policy);

    const attemptsOverride =
      envelope.metadata.canOverrideInstructions === true ||
      detectInstructionOverrideAttempt(envelope.content);

    if (envelope.intent === "memory-write" && !policy.writableMemorySources.includes(envelope.source)) {
      blockedEnvelopes.push(envelope);
      warnings.push(`Blocked memory write from ${envelope.source}.`);
      continue;
    }

    if (policy.instructionSources.includes(envelope.source) && envelope.intent === "instruction") {
      if (attemptsOverride && !policy.overrideSources.includes(envelope.source)) {
        blockedEnvelopes.push(envelope);
        warnings.push(`Blocked instruction override attempt from ${envelope.source}.`);
        continue;
      }

      instructionEnvelopes.push(envelope);
      continue;
    }

    if (attemptsOverride) {
      blockedEnvelopes.push(envelope);
      warnings.push(`Blocked instruction-like content from ${envelope.source}.`);
      continue;
    }

    referenceEnvelopes.push({
      ...envelope,
      intent: envelope.intent === "instruction" ? "reference" : envelope.intent
    });
  }

  return {
    instructionEnvelopes,
    referenceEnvelopes,
    blockedEnvelopes,
    warnings
  };
}
