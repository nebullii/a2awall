import type { Request, Response, NextFunction } from "express";
import type { SecurityPolicy } from "./policy.js";
import { evaluateAdmission, type IdentityResolver } from "./admission.js";
import { admittedRequestContext, type TaskOwnershipRegistry } from "./tasks.js";

export interface AuditEvent {
  event: "agent_request_admitted" | "agent_request_denied" | "agent_request_error";
  timestamp: string;
  path: string;
  method: string;
  jsonRpcMethod?: string;
  methodScope?: string;
  taskId?: string;
  requestId: string;
  principalId?: string;
  capability?: string;
  trustTier?: string;
  scopes?: string[];
  riskLevel?: string;
  toolAccess?: string;
  statusCode?: number;
  reasons: string[];
}

export interface AuditLogger {
  log(event: AuditEvent): void;
}

export const consoleAuditLogger: AuditLogger = {
  log(event) {
    console.log(JSON.stringify(event));
  }
};

export interface SecurityMiddlewareOptions {
  identityResolver?: IdentityResolver;
  auditLogger?: AuditLogger;
  taskOwnership?: TaskOwnershipRegistry;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * A2A 1.0 assigns no JSON-RPC error code for authentication or authorization
 * failure, and does not say whether the JSON-RPC binding should report such a
 * failure at the transport layer or in the response body. A2AWall does both: it
 * keeps the HTTP status that the specification names for auth errors, and also
 * returns a well-formed JSON-RPC error object so that clients which always
 * parse `response.error` are not left with an unparseable body.
 *
 * These codes sit in the reserved -32000..-32099 implementation range and
 * deliberately avoid -32001..-32008, which A2A has already assigned.
 */
const JSON_RPC_ERROR_CODES: Record<string, number> = {
  unauthorized: -32010,
  forbidden: -32011,
  approval_required: -32012,
  payload_too_large: -32013,
  capability_required: -32602,
  capability_conflict: -32602,
  internal_error: -32603
};

function isJsonRpcRequest(request: Request): boolean {
  const body = request.body as { jsonrpc?: unknown } | undefined;
  return body?.jsonrpc === "2.0";
}

function getJsonRpcId(request: Request): string | number | null {
  const body = request.body as { id?: unknown } | undefined;
  if (typeof body?.id === "string" || typeof body?.id === "number") {
    return body.id;
  }

  return null;
}

function writeError(
  request: Request,
  response: Response,
  statusCode: number,
  errorCode: string,
  message: string
) {
  if (statusCode === 401) {
    response.setHeader("WWW-Authenticate", 'Bearer realm="a2awall"');
  }

  if (!isJsonRpcRequest(request)) {
    response.status(statusCode).json({ error: { code: errorCode, message } });
    return;
  }

  response.status(statusCode).json({
    jsonrpc: "2.0",
    id: getJsonRpcId(request),
    error: {
      code: JSON_RPC_ERROR_CODES[errorCode] ?? -32000,
      message,
      data: {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        reason: errorCode.toUpperCase(),
        domain: "a2awall"
      }
    }
  });
}

/**
 * Accepts a caller-supplied correlation id only if it is short and free of
 * control characters, so that a caller cannot shape the audit record.
 */
function safeRequestId(candidate: string | undefined): string {
  if (candidate && REQUEST_ID_PATTERN.test(candidate)) {
    return candidate;
  }

  return crypto.randomUUID();
}

function getJsonRpcMethod(request: Request): string | undefined {
  const body = request.body as { method?: unknown } | undefined;
  return typeof body?.method === "string" ? body.method : undefined;
}

/**
 * Rewrites the request so that every downstream reader sees exactly the
 * capability that admission authorised, and removes the alternate declaration
 * sites so none of them can be read instead.
 */
function normalizeCapability(request: Request, policy: SecurityPolicy, capability: string) {
  const metadataKey = policy.metadata.capabilityMetadataKey;
  request.headers[policy.metadata.capabilityHeader] = capability;

  const body = request.body as
    | {
        metadata?: Record<string, unknown>;
        params?: {
          metadata?: Record<string, unknown>;
          message?: { metadata?: Record<string, unknown> };
        };
        message?: { metadata?: Record<string, unknown> };
      }
    | undefined;

  if (!body || typeof body !== "object") {
    return;
  }

  delete body.metadata?.[metadataKey];
  delete body.params?.metadata?.[metadataKey];

  // The JSON-RPC binding nests the message under `params`; the REST binding
  // puts it at the top level. Normalise whichever one is present.
  const message = body.params?.message ?? body.message;
  if (message) {
    message.metadata = {
      ...message.metadata,
      [metadataKey]: capability
    };
  }
}

export function createSecurityMiddleware(
  policy: SecurityPolicy,
  options: SecurityMiddlewareOptions = {}
) {
  const auditLogger = options.auditLogger ?? consoleAuditLogger;

  return async function securityMiddleware(
    request: Request,
    response: Response,
    next: NextFunction
  ) {
    const requestIdHeader = policy.metadata.requestIdHeader;
    const baseEvent = {
      timestamp: new Date().toISOString(),
      path: request.path,
      method: request.method,
      jsonRpcMethod: getJsonRpcMethod(request)
    };

    let decision;
    try {
      decision = await evaluateAdmission(request, policy, {
        identityResolver: options.identityResolver,
        taskOwnership: options.taskOwnership
      });
    } catch (error) {
      const requestId = safeRequestId(request.header(requestIdHeader));
      auditLogger.log({
        ...baseEvent,
        event: "agent_request_error",
        requestId,
        statusCode: 500,
        reasons: ["admission_error"]
      });
      response.setHeader(requestIdHeader, requestId);
      writeError(request, response, 500, "internal_error", "Request rejected by gateway policy.");
      return;
    }

    if (!decision.allowed || !decision.context) {
      const requestId = safeRequestId(request.header(requestIdHeader));
      const statusCode = decision.statusCode ?? 401;

      // Denials are logged with the same fidelity as admissions: a gateway that
      // only records successes cannot evidence an attempted bypass.
      auditLogger.log({
        ...baseEvent,
        event: "agent_request_denied",
        requestId,
        statusCode,
        riskLevel: decision.riskLevel,
        reasons: decision.reasons
      });

      response.setHeader(requestIdHeader, requestId);
      writeError(
        request,
        response,
        statusCode,
        decision.errorCode ?? "unauthorized",
        decision.message ?? "Request rejected by gateway policy."
      );
      return;
    }

    const { capability, capabilityPolicy, identity, requestId, method } = decision.context;

    response.setHeader(requestIdHeader, requestId);
    request.headers[requestIdHeader] = requestId;
    request.headers["x-caller-id"] = identity.principalId;

    if (capability) {
      normalizeCapability(request, policy, capability);
    }

    if (capabilityPolicy) {
      response.setHeader("x-risk-level", capabilityPolicy.riskLevel);
      response.setHeader("x-tool-access", capabilityPolicy.toolAccess);
    }

    auditLogger.log({
      ...baseEvent,
      event: "agent_request_admitted",
      jsonRpcMethod: method.name,
      methodScope: method.scope,
      taskId: method.taskId,
      requestId,
      principalId: identity.principalId,
      capability,
      trustTier: identity.trustTier,
      scopes: identity.scopes,
      riskLevel: capabilityPolicy?.riskLevel,
      toolAccess: capabilityPolicy?.toolAccess,
      statusCode: 200,
      reasons: decision.reasons
    });

    // Carry the decision through the async chain so the task store can bind
    // ownership to the admitted principal.
    admittedRequestContext.run(
      { principalId: identity.principalId, capability: capability ?? "", requestId },
      () => next()
    );
  };
}
