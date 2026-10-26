import { createHash, timingSafeEqual } from "node:crypto";
import type { Request } from "express";
import {
  hashToken,
  trustTierSatisfies,
  type CapabilityPolicy,
  type RiskLevel,
  type SecurityIdentity,
  type SecurityPolicy
} from "./policy.js";
import { resolveMethod, type ResolvedMethod } from "./methods.js";
import type { TaskOwnershipRegistry } from "./tasks.js";

export interface AdmissionContext {
  identity: SecurityIdentity;
  requestId: string;
  messageText: string;
  /** How the request was authorized. */
  method: ResolvedMethod;
  /**
   * Present for capability-scoped requests, and for task-scoped requests, where
   * it is the capability the task was created under rather than anything the
   * caller declared. Absent for requests authorized by authentication alone.
   */
  capability?: string;
  capabilityPolicy?: CapabilityPolicy;
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

export interface PresentedCredential {
  scheme: string;
  token: string;
}

/**
 * Resolves a presented credential to an identity, or undefined to reject.
 *
 * This is the seam for real credential verification. The built-in resolver
 * compares opaque bearer tokens, which is a development mechanism. A production
 * deployment should supply a resolver that verifies a signed token and checks
 * its issuer, audience and expiry before mapping claims onto an identity.
 */
export interface IdentityResolver {
  resolve(
    credential: PresentedCredential,
    request: Request
  ): Promise<SecurityIdentity | undefined> | SecurityIdentity | undefined;
}

function digestOf(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Compares two SHA-256 digests without leaking the position of the difference. */
function digestsMatch(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Matches opaque bearer tokens against the policy's identities in constant
 * time: every identity is compared on every request, and the comparison is over
 * SHA-256 digests rather than the raw secrets.
 */
export function createStaticTokenResolver(policy: SecurityPolicy): IdentityResolver {
  const entries = policy.identities.map((identity) => ({
    identity,
    digest: Buffer.from(identity.tokenSha256 ?? hashToken(identity.token ?? ""), "hex")
  }));

  return {
    resolve(credential) {
      if (credential.scheme.toLowerCase() !== "bearer") {
        return undefined;
      }

      const presented = digestOf(credential.token);
      let matched: SecurityIdentity | undefined;

      for (const entry of entries) {
        if (digestsMatch(entry.digest, presented)) {
          matched = entry.identity;
        }
      }

      return matched;
    }
  };
}

function getCredential(request: Request): PresentedCredential | undefined {
  const authHeader = request.header("authorization");
  if (!authHeader) {
    return undefined;
  }

  const [scheme, ...rest] = authHeader.trim().split(/\s+/);
  if (!scheme || rest.length === 0) {
    return undefined;
  }

  return { scheme, token: rest.join(" ") };
}

type MessageBody = {
  /** JSON-RPC / 0.3 wire format. */
  parts?: Array<Record<string, unknown>>;
  /** proto-JSON wire format, used by the REST binding and by A2A 1.0. */
  content?: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
};

type RequestBody = {
  method?: string;
  metadata?: Record<string, unknown>;
  /** JSON-RPC binding: the message is nested under `params`. */
  params?: {
    metadata?: Record<string, unknown>;
    message?: MessageBody;
  };
  /** REST binding: the message is at the top level. */
  message?: MessageBody;
};

function getBody(request: Request): RequestBody {
  if (!request.body || typeof request.body !== "object") {
    return {};
  }

  return request.body as RequestBody;
}

/**
 * Resolves the message regardless of transport binding. The JSON-RPC binding
 * nests it under `params`, the REST binding puts it at the top level. A check
 * that understands only one shape silently passes every request on the other.
 */
export function getMessageBody(request: Request): MessageBody | undefined {
  const body = getBody(request);
  return body.params?.message ?? body.message;
}

/**
 * Returns the message's parts under either field name. The JSON-RPC binding
 * calls them `parts`; the REST binding decodes proto-JSON, which calls them
 * `content`. Reading only one name means the other transport is measured as
 * empty, so every size check on it passes.
 */
function getMessageParts(request: Request): Array<Record<string, unknown>> {
  const message = getMessageBody(request);
  return message?.parts ?? message?.content ?? [];
}

/**
 * Collects every location a capability can be declared. The A2A-native location
 * is the message's own `metadata`, which is what reaches the executor; the header
 * and the outer metadata objects are accepted as hints. Any disagreement
 * between them is rejected rather than resolved by precedence, because a
 * precedence rule is what lets a caller be admitted under one capability and
 * executed under another.
 */
function collectDeclaredCapabilities(request: Request, policy: SecurityPolicy): string[] {
  const body = getBody(request);
  const metadataKey = policy.metadata.capabilityMetadataKey;

  const candidates = [
    request.header(policy.metadata.capabilityHeader),
    body.metadata?.[metadataKey],
    body.params?.metadata?.[metadataKey],
    getMessageBody(request)?.metadata?.[metadataKey]
  ];

  const declared = candidates.filter(
    (value): value is string => typeof value === "string" && value.length > 0
  );

  return [...new Set(declared)];
}

/**
 * Recognises a text part by the presence of its payload rather than by the
 * `kind` discriminator. A2A 1.0 drops `kind` from the wire format, and a
 * discriminator-based filter would silently match nothing there, so every
 * text-derived check would pass without inspecting anything.
 */
function isTextPart(part: Record<string, unknown>): part is { text: string } {
  return typeof part.text === "string";
}

function getMessageText(request: Request): string {
  const parts = getMessageParts(request);

  return parts
    .filter(isTextPart)
    .map((part) => part.text)
    .join("\n")
    .trim();
}

/**
 * Sizes the whole message, not only its text. A size limit that counts text
 * parts alone is bypassed by moving the payload into a file or data part.
 */
function measureMessagePayload(request: Request): number {
  const parts = getMessageParts(request);
  let total = 0;

  for (const part of parts) {
    if (isTextPart(part)) {
      total += part.text.length;
      continue;
    }

    const file = part.file as { bytes?: unknown; uri?: unknown } | undefined;
    if (file && typeof file === "object") {
      if (typeof file.bytes === "string") {
        total += file.bytes.length;
      }
      if (typeof file.uri === "string") {
        total += file.uri.length;
      }
      continue;
    }

    if (part.data !== undefined) {
      try {
        total += JSON.stringify(part.data)?.length ?? 0;
      } catch {
        // A payload that cannot be serialised cannot be sized; charge the
        // full budget so it is rejected rather than admitted unmeasured.
        return Number.MAX_SAFE_INTEGER;
      }
    }
  }

  return total;
}

function verifyApprovalToken(request: Request, policy: SecurityPolicy): boolean {
  const presentedToken = request.header(policy.metadata.approvalHeader);
  if (!presentedToken) {
    return false;
  }

  const accepted = policy.approval?.tokenSha256 ?? [];
  if (accepted.length === 0) {
    return false;
  }

  const presented = digestOf(presentedToken);
  let matched = false;
  for (const expected of accepted) {
    if (digestsMatch(Buffer.from(expected, "hex"), presented)) {
      matched = true;
    }
  }

  return matched;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Accepts a caller-supplied correlation id only when it is short and free of
 * control characters, so a caller cannot shape the audit record.
 */
function safeRequestId(candidate: string | undefined): string {
  if (candidate && REQUEST_ID_PATTERN.test(candidate)) {
    return candidate;
  }

  return crypto.randomUUID();
}

function reject(
  statusCode: number,
  errorCode: string,
  message: string,
  reason: string,
  riskLevel?: RiskLevel
): AdmissionDecision {
  return {
    allowed: false,
    statusCode,
    errorCode,
    message,
    reasons: [reason],
    riskLevel
  };
}

export interface EvaluateAdmissionOptions {
  identityResolver?: IdentityResolver;
  /**
   * Required to authorize task-scoped methods. Without it, every task-scoped
   * request is refused rather than admitted unchecked.
   */
  taskOwnership?: TaskOwnershipRegistry;
}

export async function evaluateAdmission(
  request: Request,
  policy: SecurityPolicy,
  options: EvaluateAdmissionOptions = {}
): Promise<AdmissionDecision> {
  const resolver = options.identityResolver ?? createStaticTokenResolver(policy);

  const credential = getCredential(request);
  const identity = credential ? await resolver.resolve(credential, request) : undefined;
  if (!identity) {
    return reject(401, "unauthorized", "Missing or invalid bearer token.", "missing_identity");
  }

  const requestId = safeRequestId(request.header(policy.metadata.requestIdHeader));
  const method = resolveMethod(request);

  // Default deny. A method this version does not classify must not reach the
  // agent just because the caller authenticated.
  if (method.scope === "unsupported") {
    return reject(
      400,
      "method_not_supported",
      `Method '${method.name}' is not supported by this gateway.`,
      "method_not_supported"
    );
  }

  // Authorized by authentication alone; carries neither a message nor a task.
  if (method.scope === "card") {
    return {
      allowed: true,
      reasons: ["admitted"],
      context: { identity, requestId, messageText: "", method }
    };
  }

  // Task-scoped: authorized by ownership of the named task, never by a
  // capability the caller declares. Task identifiers are handed to callers and
  // travel between agents, so they are not secrets.
  if (method.scope === "task") {
    if (!method.taskId) {
      return reject(
        400,
        "task_required",
        `Method '${method.name}' must name a task.`,
        "task_id_missing"
      );
    }

    const registry = options.taskOwnership;
    if (!registry) {
      return reject(
        403,
        "forbidden",
        "Task-scoped methods are unavailable because no task ownership registry is configured.",
        "task_ownership_unavailable"
      );
    }

    if (!registry.isOwnedBy(method.taskId, identity.principalId)) {
      // The same answer for an unknown task and for another principal's task,
      // so that existence cannot be probed.
      return reject(
        404,
        "task_not_found",
        `Task '${method.taskId}' was not found.`,
        "task_not_owned"
      );
    }

    const owningCapability = registry.get(method.taskId)?.capability;
    return {
      allowed: true,
      reasons: ["admitted"],
      riskLevel: owningCapability
        ? policy.capabilityPolicies[owningCapability]?.riskLevel
        : undefined,
      context: {
        identity,
        requestId,
        messageText: "",
        method,
        capability: owningCapability,
        capabilityPolicy: owningCapability
          ? policy.capabilityPolicies[owningCapability]
          : undefined
      }
    };
  }

  const declaredCapabilities = collectDeclaredCapabilities(request, policy);
  if (declaredCapabilities.length === 0) {
    return reject(
      400,
      "capability_required",
      `Request must declare a capability in '${policy.metadata.capabilityHeader}' or in message metadata '${policy.metadata.capabilityMetadataKey}'.`,
      "capability_missing"
    );
  }

  if (declaredCapabilities.length > 1) {
    return reject(
      400,
      "capability_conflict",
      `Request declares conflicting capabilities: ${declaredCapabilities.join(", ")}.`,
      "capability_conflict"
    );
  }

  const capability = declaredCapabilities[0]!;
  const capabilityPolicy = policy.capabilityPolicies[capability];
  if (!capabilityPolicy) {
    return reject(
      403,
      "forbidden",
      `Capability '${capability}' is not allowed.`,
      "unknown_capability"
    );
  }

  if (identity.allowedCapabilities && !identity.allowedCapabilities.includes(capability)) {
    return reject(
      403,
      "forbidden",
      `Caller '${identity.principalId}' cannot use capability '${capability}'.`,
      "capability_not_granted",
      capabilityPolicy.riskLevel
    );
  }

  const hasRequiredScopes = capabilityPolicy.requiredScopes.every((scope) =>
    identity.scopes.includes(scope)
  );
  if (!hasRequiredScopes) {
    return reject(
      403,
      "forbidden",
      `Caller '${identity.principalId}' is missing required scopes for capability '${capability}'.`,
      "missing_scope",
      capabilityPolicy.riskLevel
    );
  }

  if (!trustTierSatisfies(identity.trustTier, capabilityPolicy.requiredTrustTier)) {
    return reject(
      403,
      "forbidden",
      `Caller '${identity.principalId}' does not meet the trust tier for capability '${capability}'.`,
      "insufficient_trust_tier",
      capabilityPolicy.riskLevel
    );
  }

  if (
    capabilityPolicy.allowedPrincipals &&
    !capabilityPolicy.allowedPrincipals.includes(identity.principalId)
  ) {
    return reject(
      403,
      "forbidden",
      `Caller '${identity.principalId}' is not allowed to use capability '${capability}'.`,
      "principal_not_allowed",
      capabilityPolicy.riskLevel
    );
  }

  if (capabilityPolicy.approvalRequired && !verifyApprovalToken(request, policy)) {
    return reject(
      403,
      "approval_required",
      `Capability '${capability}' requires a valid approval token.`,
      "approval_invalid",
      capabilityPolicy.riskLevel
    );
  }

  if (measureMessagePayload(request) > capabilityPolicy.maxMessageCharacters) {
    return reject(
      413,
      "payload_too_large",
      `Capability '${capability}' exceeded the maximum message size.`,
      "message_too_large",
      capabilityPolicy.riskLevel
    );
  }

  return {
    allowed: true,
    reasons: ["admitted"],
    riskLevel: capabilityPolicy.riskLevel,
    context: {
      capability,
      identity,
      capabilityPolicy,
      requestId,
      messageText: getMessageText(request),
      method
    }
  };
}
