export type ContextSource =
  | "system"
  | "developer"
  | "user"
  | "memory"
  | "retrieval"
  | "tool"
  | "peer-agent";

export type TrustLabel = "trusted" | "verified" | "untrusted";
export type ContextIntent = "instruction" | "reference" | "memory-write" | "tool-result";

export interface ContextEnvelopeMetadata {
  canOverrideInstructions?: boolean;
  provenance?: string;
  tags?: string[];
  actorId?: string;
}

export interface ContextEnvelopeInput {
  id?: string;
  source: ContextSource;
  trustLabel?: TrustLabel;
  intent?: ContextIntent;
  content: string;
  createdAt?: string;
  metadata?: ContextEnvelopeMetadata;
}

export interface ContextEnvelope {
  id: string;
  source: ContextSource;
  trustLabel: TrustLabel;
  intent: ContextIntent;
  content: string;
  createdAt: string;
  metadata: ContextEnvelopeMetadata;
}

function defaultTrustLabel(source: ContextSource): TrustLabel {
  if (source === "system" || source === "developer") {
    return "trusted";
  }

  return "untrusted";
}

function defaultIntent(source: ContextSource): ContextIntent {
  if (source === "system" || source === "developer") {
    return "instruction";
  }

  if (source === "tool") {
    return "tool-result";
  }

  return "reference";
}

export function createContextEnvelope(input: ContextEnvelopeInput): ContextEnvelope {
  return {
    id: input.id ?? crypto.randomUUID(),
    source: input.source,
    trustLabel: input.trustLabel ?? defaultTrustLabel(input.source),
    intent: input.intent ?? defaultIntent(input.source),
    content: input.content,
    createdAt: input.createdAt ?? new Date().toISOString(),
    metadata: input.metadata ?? {}
  };
}
