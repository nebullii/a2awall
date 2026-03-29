export type RetrievalTrust = "trusted" | "verified" | "untrusted";
export type RetrievalDisposition = "allow" | "reference-only" | "quarantine";

export interface RetrievedDocument {
  id: string;
  source: string;
  content: string;
  trust: RetrievalTrust;
  freshness?: string;
  provenance?: string;
}

export interface RetrievalPolicy {
  trustedSources: string[];
  verifiedSources: string[];
  maxDocumentCharacters: number;
}

export interface RetrievalDecision {
  document: RetrievedDocument;
  disposition: RetrievalDisposition;
  reasons: string[];
}

export function evaluateRetrievedDocument(
  document: RetrievedDocument,
  policy: RetrievalPolicy
): RetrievalDecision {
  if (document.content.length > policy.maxDocumentCharacters) {
    return {
      document,
      disposition: "quarantine",
      reasons: ["document_too_large"]
    };
  }

  if (policy.trustedSources.includes(document.source) && document.trust === "trusted") {
    return {
      document,
      disposition: "allow",
      reasons: ["trusted_source"]
    };
  }

  if (policy.verifiedSources.includes(document.source) || document.trust === "verified") {
    return {
      document,
      disposition: "reference-only",
      reasons: ["verified_reference_only"]
    };
  }

  return {
    document,
    disposition: "quarantine",
    reasons: ["untrusted_source"]
  };
}
