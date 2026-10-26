import type { Request } from "express";

/**
 * How a request must be authorized.
 *
 * - `capability`: the request carries a message and is authorized against a
 *   capability policy.
 * - `task`: the request names an existing task and is authorized by ownership of
 *   that task, not by a capability declaration.
 * - `card`: the authenticated extended card. Authentication only.
 * - `unsupported`: anything else. Default deny, so a method added by a future
 *   SDK version cannot reach the agent unreviewed.
 */
export type MethodScope = "capability" | "task" | "card" | "unsupported";

export interface ResolvedMethod {
  /** The method name, or the REST route that stands in for it. */
  name: string;
  scope: MethodScope;
  /** Present for task-scoped requests. */
  taskId?: string;
}

const CAPABILITY_SCOPED_METHODS = new Set(["message/send", "message/stream"]);

const TASK_SCOPED_METHODS = new Set([
  "tasks/get",
  "tasks/cancel",
  "tasks/resubscribe",
  "tasks/pushNotificationConfig/set",
  "tasks/pushNotificationConfig/get",
  "tasks/pushNotificationConfig/list",
  "tasks/pushNotificationConfig/delete"
]);

const CARD_SCOPED_METHODS = new Set(["agent/getAuthenticatedExtendedCard"]);

function getTaskIdFromParams(params: unknown): string | undefined {
  if (!params || typeof params !== "object") {
    return undefined;
  }

  const candidate = params as { id?: unknown; taskId?: unknown };
  if (typeof candidate.taskId === "string" && candidate.taskId.length > 0) {
    return candidate.taskId;
  }

  return typeof candidate.id === "string" && candidate.id.length > 0 ? candidate.id : undefined;
}

/**
 * Classifies a REST route. `request.path` is relative to the mount point, so
 * these are the paths the SDK's REST router registers beneath it.
 */
function resolveRestRoute(path: string): ResolvedMethod {
  const normalized = path.replace(/\/+$/, "") || "/";

  if (normalized === "/v1/card") {
    return { name: "GET /v1/card", scope: "card" };
  }

  if (normalized === "/v1/message:send" || normalized === "/v1/message:stream") {
    return { name: `POST ${normalized}`, scope: "capability" };
  }

  const taskMatch = normalized.match(
    /^\/v1\/tasks\/([^/:]+)(?::cancel|:subscribe|\/pushNotificationConfigs(?:\/[^/]+)?)?$/
  );
  if (taskMatch?.[1]) {
    return {
      name: `${normalized}`,
      scope: "task",
      taskId: decodeURIComponent(taskMatch[1])
    };
  }

  return { name: normalized, scope: "unsupported" };
}

/**
 * Determines how the request must be authorized, from the JSON-RPC method name
 * when present and from the REST route otherwise.
 */
export function resolveMethod(request: Request): ResolvedMethod {
  const body = request.body as { jsonrpc?: unknown; method?: unknown; params?: unknown } | undefined;

  if (body && typeof body === "object" && typeof body.method === "string") {
    const name = body.method;

    if (CAPABILITY_SCOPED_METHODS.has(name)) {
      return { name, scope: "capability" };
    }

    if (TASK_SCOPED_METHODS.has(name)) {
      return { name, scope: "task", taskId: getTaskIdFromParams(body.params) };
    }

    if (CARD_SCOPED_METHODS.has(name)) {
      return { name, scope: "card" };
    }

    return { name, scope: "unsupported" };
  }

  return resolveRestRoute(request.path);
}
