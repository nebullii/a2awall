import type { CapabilityPolicy } from "../security/policy.js";
import { evaluateToolInvocation, type SandboxPolicy } from "./sandbox.js";
import { ToolRegistry } from "./tools.js";
import { validateActionProposal } from "../validation/output.js";

export interface SecureRuntimeRequest {
  requestId: string;
  callerId: string;
  capability: string;
  capabilityPolicy: CapabilityPolicy;
  summary: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  requiresApproval: boolean;
  evidence?: Array<{ source: string; quote?: string }>;
  invocation: {
    toolId: string;
    operation: "read" | "write" | "execute";
    input: Record<string, string>;
  };
}

export class SecureToolRuntime {
  constructor(private readonly registry: ToolRegistry) {}

  async executeValidatedAction(request: SecureRuntimeRequest): Promise<{ text: string }> {
    const validationDecision = validateActionProposal(
      {
        actionType: request.invocation.toolId,
        summary: request.summary,
        riskLevel: request.riskLevel,
        requiresApproval: request.requiresApproval,
        evidence: request.evidence ?? []
      },
      {
        requireEvidenceForRiskLevels: ["high", "critical"],
        maxSummaryCharacters: request.capabilityPolicy.maxMessageCharacters
      }
    );

    if (!validationDecision.valid) {
      throw new Error(`Output validation failed: ${validationDecision.reasons.join(", ")}`);
    }

    const tool = this.registry.get(request.invocation.toolId);
    if (!tool) {
      throw new Error(`Unknown tool '${request.invocation.toolId}'.`);
    }

    const sandboxPolicy: SandboxPolicy = {
      capability: request.capability,
      riskLevel: request.capabilityPolicy.riskLevel,
      toolAccess: request.capabilityPolicy.toolAccess,
      allowedToolIds: request.capabilityPolicy.allowedToolIds,
      maxRuntimeMs: request.capabilityPolicy.maxRuntimeMs,
      maxToolCalls: request.capabilityPolicy.maxToolCalls,
      networkDomains: request.capabilityPolicy.networkDomains,
      filesystemPrefixes: request.capabilityPolicy.filesystemPrefixes
    };

    const sandboxDecision = evaluateToolInvocation(sandboxPolicy, tool, {
      toolId: request.invocation.toolId,
      operation: request.invocation.operation,
      target: request.invocation.input.target,
      toolCallCount: 0
    });

    if (!sandboxDecision.allowed) {
      throw new Error(`Sandbox denied tool execution: ${sandboxDecision.reasons.join(", ")}`);
    }

    return tool.execute(
      {
        ...request.invocation.input,
        callerId: request.callerId
      },
      {
        requestId: request.requestId,
        capability: request.capability
      }
    );
  }
}
