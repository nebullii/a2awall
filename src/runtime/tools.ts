import type { ToolDefinition, ToolOperation } from "./sandbox.js";

export interface ToolExecutionContext {
  requestId: string;
  capability: string;
}

export interface RegisteredTool extends ToolDefinition {
  execute(
    input: Record<string, string>,
    context: ToolExecutionContext
  ): Promise<{ text: string }>;
}

export class ToolRegistry {
  private readonly tools = new Map<string, RegisteredTool>();

  register(tool: RegisteredTool) {
    this.tools.set(tool.id, tool);
  }

  get(toolId: string): RegisteredTool | undefined {
    return this.tools.get(toolId);
  }
}

export function createTemplateRenderTool(): RegisteredTool {
  return {
    id: "template-render",
    kind: "internal-api",
    operations: ["read" satisfies ToolOperation],
    async execute(input, context) {
      const message = input.message ?? "";
      const callerId = input.callerId ?? "anonymous";

      return {
        text: `[template:${context.capability}] ${callerId} -> ${message}`
      };
    }
  };
}
