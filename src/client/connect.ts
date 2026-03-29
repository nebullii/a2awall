import {
  ClientFactory,
  ClientFactoryOptions,
  DefaultAgentCardResolver,
  JsonRpcTransportFactory,
  RestTransportFactory,
  type Client
} from "@a2a-js/sdk/client";
import type { AgentCard, Message, MessageSendParams, Task } from "@a2a-js/sdk";

export interface ConnectOptions {
  baseUrl: string;
  bearerToken?: string;
  callerId?: string;
}

export interface SendTextOptions {
  message: string;
  capability?: string;
  contextId?: string;
  taskId?: string;
}

export interface ConnectedAgent {
  card: AgentCard;
  client: Client;
}

function createStaticHeaderFetch(options: ConnectOptions): typeof fetch {
  return async (input, init) => {
    const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
    const headers = new Headers(request.headers);
    if (options.bearerToken) {
      headers.set("authorization", `Bearer ${options.bearerToken}`);
    }
    if (options.callerId) {
      headers.set("x-caller-id", options.callerId);
    }

    return fetch(new Request(request, { headers }));
  };
}

function getTextFromResult(result: Message | Task): string {
  if (result.kind === "message") {
    return result.parts
      .filter((part): part is Extract<typeof part, { kind: "text" }> => part.kind === "text")
      .map((part) => part.text)
      .join("\n")
      .trim();
  }

  const statusText = result.status.message?.parts
    ?.filter((part): part is Extract<typeof part, { kind: "text" }> => part.kind === "text")
    .map((part) => part.text)
    .join("\n")
    .trim();

  return statusText || `Task ${result.id} is in state ${result.status.state}.`;
}

export async function connectToAgent(options: ConnectOptions): Promise<ConnectedAgent> {
  const fetchImpl = createStaticHeaderFetch(options);
  const factoryOptions = ClientFactoryOptions.createFrom(ClientFactoryOptions.default, {
    cardResolver: new DefaultAgentCardResolver({ fetchImpl }),
    transports: [new JsonRpcTransportFactory({ fetchImpl }), new RestTransportFactory({ fetchImpl })]
  });

  const factory = new ClientFactory(factoryOptions);
  const client = await factory.createFromUrl(options.baseUrl);
  const card = await client.getAgentCard();

  return { client, card };
}

export async function sendTextToAgent(
  connection: ConnectedAgent,
  options: SendTextOptions
): Promise<{ raw: Message | Task; text: string }> {
  const params: MessageSendParams = {
    message: {
      kind: "message",
      messageId: crypto.randomUUID(),
      role: "user",
      contextId: options.contextId,
      taskId: options.taskId,
      parts: [{ kind: "text", text: options.message }],
      metadata: options.capability ? { capability: options.capability } : undefined
    }
  };

  const result = await connection.client.sendMessage(params);

  return {
    raw: result,
    text: getTextFromResult(result)
  };
}
