export interface AgentTask {
  taskId: string;
  message: string;
  capability?: string;
  acceptedOutputModes?: string[];
}

export interface AgentContext {
  callerId: string;
  requestId: string;
}

export interface AgentResult {
  text: string;
}

export interface AgentCapability {
  id: string;
  name: string;
  description: string;
}

export interface CustomAgent {
  id: string;
  name: string;
  description: string;
  version?: string;
  capabilities: AgentCapability[];
  run(task: AgentTask, context: AgentContext): Promise<AgentResult>;
}
