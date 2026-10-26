import { AsyncLocalStorage } from "node:async_hooks";
import type { Task } from "@a2a-js/sdk";
import type { TaskStore } from "@a2a-js/sdk/server";

export interface AdmittedRequestContext {
  principalId: string;
  capability: string;
  requestId: string;
}

/**
 * Carries the admission decision through the asynchronous call chain, so that
 * components below the HTTP layer, such as the task store, can see which
 * principal the current request belongs to without it being threaded through
 * the A2A SDK's own interfaces.
 */
export const admittedRequestContext = new AsyncLocalStorage<AdmittedRequestContext>();

export interface TaskOwnershipRecord {
  principalId: string;
  capability: string;
  createdAt: number;
}

export interface TaskOwnershipRegistryOptions {
  /**
   * Bound on retained records. The registry evicts the oldest entries beyond
   * this, so a caller cannot grow it without limit by creating tasks.
   */
  maxEntries?: number;
}

/**
 * Records which principal created each task.
 *
 * A2A task identifiers are handed to the caller and travel through multi-agent
 * conversations, so they are not secrets. Without an ownership check, any
 * authenticated caller that learns an identifier can read or cancel another
 * caller's task.
 *
 * This implementation is in-process. A deployment running more than one gateway
 * instance needs a shared store, otherwise ownership is only known to the
 * instance that admitted the creating request.
 */
export class TaskOwnershipRegistry {
  private readonly records = new Map<string, TaskOwnershipRecord>();
  private readonly maxEntries: number;

  constructor(options: TaskOwnershipRegistryOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
  }

  record(taskId: string, context: AdmittedRequestContext): void {
    if (this.records.has(taskId)) {
      return;
    }

    if (this.records.size >= this.maxEntries) {
      const oldest = this.records.keys().next();
      if (!oldest.done) {
        this.records.delete(oldest.value);
      }
    }

    this.records.set(taskId, {
      principalId: context.principalId,
      capability: context.capability,
      createdAt: Date.now()
    });
  }

  get(taskId: string): TaskOwnershipRecord | undefined {
    return this.records.get(taskId);
  }

  /**
   * An unknown task is treated as not owned by the caller. Combined with the
   * gateway returning the same error for unknown and unauthorized tasks, this
   * keeps the existence of another principal's task from being probed.
   */
  isOwnedBy(taskId: string, principalId: string): boolean {
    return this.records.get(taskId)?.principalId === principalId;
  }

  get size(): number {
    return this.records.size;
  }
}

/**
 * Wraps a task store so that ownership is recorded on write and enforced on
 * read. The admission layer already refuses a task-scoped request from a
 * principal that does not own the task; this is the second, independent check,
 * so a future transport or method that reaches the store without passing that
 * check still cannot cross principals.
 */
export function createOwnershipScopedTaskStore(
  inner: TaskStore,
  registry: TaskOwnershipRegistry
): TaskStore {
  return {
    async save(task: Task): Promise<void> {
      const context = admittedRequestContext.getStore();
      if (context) {
        registry.record(task.id, context);
      }

      return inner.save(task);
    },

    async load(taskId: string): Promise<Task | undefined> {
      const context = admittedRequestContext.getStore();
      if (context && !registry.isOwnedBy(taskId, context.principalId)) {
        const owner = registry.get(taskId);
        if (owner) {
          throw new Error(
            `Principal '${context.principalId}' is not the owner of task '${taskId}'.`
          );
        }
      }

      return inner.load(taskId);
    }
  };
}
