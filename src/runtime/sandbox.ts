import type { RiskLevel, ToolAccessMode } from "../security/policy.js";

export type ToolKind = "filesystem" | "network" | "database" | "internal-api" | "agent";
export type ToolOperation = "read" | "write" | "execute";

export interface ToolDefinition {
  id: string;
  kind: ToolKind;
  operations: ToolOperation[];
  allowedDomains?: string[];
  allowedPaths?: string[];
}

export interface SandboxPolicy {
  capability: string;
  riskLevel: RiskLevel;
  toolAccess: ToolAccessMode;
  allowedToolIds: string[];
  maxRuntimeMs: number;
  maxToolCalls: number;
  networkDomains?: string[];
  filesystemPrefixes?: string[];
}

export interface ToolInvocationRequest {
  toolId: string;
  operation: ToolOperation;
  target?: string;
  toolCallCount: number;
}

export interface SandboxDecision {
  allowed: boolean;
  reasons: string[];
  statusCode?: number;
  message?: string;
}

function matchesPrefix(target: string | undefined, prefixes: string[] | undefined): boolean {
  if (!target || !prefixes || prefixes.length === 0) {
    return true;
  }

  return prefixes.some((prefix) => target.startsWith(prefix));
}

function matchesDomain(target: string | undefined, allowedDomains: string[] | undefined): boolean {
  if (!target || !allowedDomains || allowedDomains.length === 0) {
    return true;
  }

  try {
    const url = new URL(target);
    return allowedDomains.includes(url.hostname);
  } catch {
    return false;
  }
}

export function evaluateToolInvocation(
  policy: SandboxPolicy,
  tool: ToolDefinition,
  request: ToolInvocationRequest
): SandboxDecision {
  if (!policy.allowedToolIds.includes(tool.id)) {
    return {
      allowed: false,
      reasons: ["tool_not_allowed"],
      statusCode: 403,
      message: `Tool '${tool.id}' is not allowed for capability '${policy.capability}'.`
    };
  }

  if (request.toolCallCount >= policy.maxToolCalls) {
    return {
      allowed: false,
      reasons: ["tool_budget_exceeded"],
      statusCode: 429,
      message: `Tool call budget exceeded for capability '${policy.capability}'.`
    };
  }

  if (!tool.operations.includes(request.operation)) {
    return {
      allowed: false,
      reasons: ["operation_not_supported"],
      statusCode: 400,
      message: `Tool '${tool.id}' does not support '${request.operation}'.`
    };
  }

  if (policy.toolAccess === "none") {
    return {
      allowed: false,
      reasons: ["tool_access_disabled"],
      statusCode: 403,
      message: `Capability '${policy.capability}' cannot invoke tools.`
    };
  }

  if (tool.kind === "network" && !matchesDomain(request.target, policy.networkDomains ?? tool.allowedDomains)) {
    return {
      allowed: false,
      reasons: ["domain_not_allowed"],
      statusCode: 403,
      message: `Network target is outside the sandbox allowlist.`
    };
  }

  if (tool.kind === "filesystem" && !matchesPrefix(request.target, policy.filesystemPrefixes ?? tool.allowedPaths)) {
    return {
      allowed: false,
      reasons: ["path_not_allowed"],
      statusCode: 403,
      message: `Filesystem target is outside the sandbox allowlist.`
    };
  }

  if (policy.toolAccess === "read-only" && request.operation !== "read") {
    return {
      allowed: false,
      reasons: ["write_not_allowed"],
      statusCode: 403,
      message: `Capability '${policy.capability}' is limited to read-only tool access.`
    };
  }

  return {
    allowed: true,
    reasons: ["sandbox_admitted"]
  };
}
