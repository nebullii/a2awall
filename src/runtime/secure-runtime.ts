import type { CapabilityPolicy, RiskLevel } from "../security/policy.js";
import { evaluateToolInvocation, type SandboxPolicy, type ToolOperation } from "./sandbox.js";
import { ToolRegistry } from "./tools.js";
import { validateActionProposal } from "../validation/output.js";

export class SecureRuntimeError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly statusCode = 403,
    readonly reasons: string[] = []
  ) {
    super(message);
    this.name = "SecureRuntimeError";
  }
}

/**
 * Tracks the tool-call and wall-clock budget for one capability invocation.
 * A budget instance must be reused across every tool call that belongs to the
 * same request, otherwise `maxToolCalls` cannot be enforced.
 */
export class ToolCallBudget {
  private calls = 0;

  constructor(
    readonly maxToolCalls: number,
    readonly maxRuntimeMs: number,
    readonly startedAtMs: number = Date.now()
  ) {}

  static fromCapabilityPolicy(policy: CapabilityPolicy): ToolCallBudget {
    return new ToolCallBudget(policy.maxToolCalls, policy.maxRuntimeMs);
  }

  get consumedCalls(): number {
    return this.calls;
  }

  get deadlineMs(): number {
    return this.startedAtMs + this.maxRuntimeMs;
  }

  get remainingMs(): number {
    return this.deadlineMs - Date.now();
  }

  get expired(): boolean {
    return this.remainingMs <= 0;
  }

  consume(): void {
    this.calls += 1;
  }
}

export interface SecureRuntimeRequest {
  requestId: string;
  callerId: string;
  capability: string;
  capabilityPolicy: CapabilityPolicy;
  summary: string;
  /**
   * Optional. The authoritative risk level is the capability policy's. Passing a
   * value that disagrees with the policy is a configuration error and is
   * rejected rather than honoured, so that a caller cannot lower its own risk
   * classification to escape the evidence and approval requirements.
   */
  riskLevel?: RiskLevel;
  /** Optional, and validated against the capability policy for the same reason. */
  requiresApproval?: boolean;
  evidence?: Array<{ source: string; quote?: string }>;
  invocation: {
    toolId: string;
    operation: ToolOperation;
    input: Record<string, string>;
  };
}

export class SecureToolRuntime {
  constructor(private readonly registry: ToolRegistry) {}

  async executeValidatedAction(
    request: SecureRuntimeRequest,
    budget: ToolCallBudget = ToolCallBudget.fromCapabilityPolicy(request.capabilityPolicy)
  ): Promise<{ text: string }> {
    const policy = request.capabilityPolicy;

    if (request.riskLevel !== undefined && request.riskLevel !== policy.riskLevel) {
      throw new SecureRuntimeError(
        "risk_level_conflict",
        `Declared risk level '${request.riskLevel}' does not match the policy risk level '${policy.riskLevel}' for capability '${request.capability}'.`,
        500,
        ["risk_level_conflict"]
      );
    }

    if (request.requiresApproval !== undefined && request.requiresApproval !== policy.approvalRequired) {
      throw new SecureRuntimeError(
        "approval_flag_conflict",
        `Declared approval requirement does not match the policy for capability '${request.capability}'.`,
        500,
        ["approval_flag_conflict"]
      );
    }

    const validationDecision = validateActionProposal(
      {
        actionType: request.invocation.toolId,
        summary: request.summary,
        riskLevel: policy.riskLevel,
        requiresApproval: policy.approvalRequired,
        evidence: request.evidence ?? []
      },
      {
        requireEvidenceForRiskLevels: ["high", "critical"],
        maxSummaryCharacters: policy.maxMessageCharacters
      }
    );

    if (!validationDecision.valid) {
      throw new SecureRuntimeError(
        "output_validation_failed",
        `Output validation failed: ${validationDecision.reasons.join(", ")}`,
        422,
        validationDecision.reasons
      );
    }

    const tool = this.registry.get(request.invocation.toolId);
    if (!tool) {
      throw new SecureRuntimeError(
        "unknown_tool",
        `Unknown tool '${request.invocation.toolId}'.`,
        400,
        ["unknown_tool"]
      );
    }

    if (budget.expired) {
      throw new SecureRuntimeError(
        "runtime_budget_exceeded",
        `Runtime budget of ${budget.maxRuntimeMs}ms exhausted for capability '${request.capability}'.`,
        504,
        ["runtime_budget_exceeded"]
      );
    }

    const sandboxPolicy: SandboxPolicy = {
      capability: request.capability,
      riskLevel: policy.riskLevel,
      toolAccess: policy.toolAccess,
      allowedToolIds: policy.allowedToolIds,
      maxRuntimeMs: policy.maxRuntimeMs,
      maxToolCalls: policy.maxToolCalls,
      networkDomains: policy.networkDomains,
      filesystemPrefixes: policy.filesystemPrefixes
    };

    const sandboxDecision = evaluateToolInvocation(sandboxPolicy, tool, {
      toolId: request.invocation.toolId,
      operation: request.invocation.operation,
      target: request.invocation.input.target,
      toolCallCount: budget.consumedCalls
    });

    if (!sandboxDecision.allowed) {
      throw new SecureRuntimeError(
        sandboxDecision.reasons[0] ?? "sandbox_denied",
        sandboxDecision.message ?? "Sandbox denied tool execution.",
        sandboxDecision.statusCode ?? 403,
        sandboxDecision.reasons
      );
    }

    // Spend the budget before execution so that a throwing or hanging tool
    // still counts against the caller's allowance.
    budget.consume();

    return this.executeWithDeadline(tool, request, budget);
  }

  private async executeWithDeadline(
    tool: NonNullable<ReturnType<ToolRegistry["get"]>>,
    request: SecureRuntimeRequest,
    budget: ToolCallBudget
  ): Promise<{ text: string }> {
    const controller = new AbortController();
    const remainingMs = Math.max(0, budget.remainingMs);
    let timer: NodeJS.Timeout | undefined;

    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(
          new SecureRuntimeError(
            "tool_execution_timeout",
            `Tool '${tool.id}' exceeded the ${budget.maxRuntimeMs}ms runtime budget for capability '${request.capability}'.`,
            504,
            ["tool_execution_timeout"]
          )
        );
      }, remainingMs);
      // Deliberately not unref'd: the deadline is a security control, so it
      // must fire even when the hanging tool is the only pending work.
    });

    try {
      // A tool that ignores the abort signal may keep running in the background,
      // but its result is discarded and never reaches the caller.
      return await Promise.race([
        tool.execute(
          {
            ...request.invocation.input,
            callerId: request.callerId
          },
          {
            requestId: request.requestId,
            capability: request.capability,
            signal: controller.signal,
            deadlineMs: budget.deadlineMs
          }
        ),
        timeout
      ]);
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }
}
