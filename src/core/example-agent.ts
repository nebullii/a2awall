import type { CustomAgent } from "./agent.js";
import { defaultSecurityPolicy, type SecurityPolicy } from "../security/policy.js";
import { SecureToolRuntime } from "../runtime/secure-runtime.js";
import { createTemplateRenderTool, ToolRegistry } from "../runtime/tools.js";

function createRuntime() {
  const registry = new ToolRegistry();
  registry.register(createTemplateRenderTool());
  return new SecureToolRuntime(registry);
}

export function createExampleAgent(policy: SecurityPolicy = defaultSecurityPolicy): CustomAgent {
  const runtime = createRuntime();

  return {
    id: "echo-agent",
    name: "Echo Agent",
    description: "A minimal custom agent used to demonstrate an A2A wrapper.",
    version: "0.2.0",
    capabilities: [
      {
        id: "echo",
        name: "Echo",
        description: "Returns the caller's message with minimal transformation."
      },
      {
        id: "template-echo",
        name: "Template Echo",
        description: "Formats the caller's message through the secure tool runtime."
      }
    ],
    async run(task, context) {
      if (task.capability === "template-echo") {
        const capabilityPolicy = policy.capabilityPolicies["template-echo"];
        if (!capabilityPolicy) {
          throw new Error(
            "Capability 'template-echo' has no policy in the active security policy."
          );
        }

        return runtime.executeValidatedAction({
          requestId: context.requestId,
          callerId: context.callerId,
          capability: "template-echo",
          capabilityPolicy,
          summary: "Format the caller message through the approved template tool.",
          evidence: [{ source: "internal:template-render" }],
          invocation: {
            toolId: "template-render",
            operation: "read",
            input: {
              message: task.message
            }
          }
        });
      }

      return {
        text: `Echo from ${context.callerId}: ${task.message}`
      };
    }
  };
}

export const exampleAgent: CustomAgent = createExampleAgent();
