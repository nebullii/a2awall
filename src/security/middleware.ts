import type { Request, Response, NextFunction } from "express";
import type { SecurityPolicy } from "./policy.js";
import { evaluateAdmission } from "./admission.js";

export function createSecurityMiddleware(policy: SecurityPolicy) {
  return function securityMiddleware(
    request: Request,
    response: Response,
    next: NextFunction
  ) {
    const decision = evaluateAdmission(request, policy);
    if (!decision.allowed || !decision.context) {
      response.status(decision.statusCode ?? 401).json({
        error: {
          code: decision.errorCode ?? "unauthorized",
          message: decision.message ?? "Request rejected by gateway policy."
        }
      });
      return;
    }

    const { capability, capabilityPolicy, identity, requestId } = decision.context;
    const requestIdHeader = policy.metadata.requestIdHeader;
    response.setHeader(requestIdHeader, requestId);
    request.headers[requestIdHeader] = requestId;
    request.headers["x-caller-id"] = identity.principalId;
    request.headers[policy.metadata.capabilityHeader] = capability;
    response.setHeader("x-risk-level", capabilityPolicy.riskLevel);
    response.setHeader("x-tool-access", capabilityPolicy.toolAccess);

    console.log(
      JSON.stringify({
        event: "agent_request",
        path: request.path,
        method: request.method,
        principalId: identity.principalId,
        capability,
        requestId,
        scopes: identity.scopes,
        trustTier: identity.trustTier,
        riskLevel: capabilityPolicy.riskLevel,
        toolAccess: capabilityPolicy.toolAccess
      })
    );

    next();
  };
}
