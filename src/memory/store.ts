import type { ContextSource } from "../context/envelope.js";

export interface MemoryEntry {
  id: string;
  tenantId: string;
  capability: string;
  content: string;
  source: ContextSource;
  provenance?: string;
  createdAt: string;
  expiresAt?: string;
}

export interface MemoryWritePolicy {
  writableSources: ContextSource[];
  maxEntriesPerTenant: number;
}

export interface MemoryWriteInput {
  tenantId: string;
  capability: string;
  content: string;
  source: ContextSource;
  provenance?: string;
  ttlSeconds?: number;
}

export interface MemoryDecision {
  allowed: boolean;
  reasons: string[];
  entry?: MemoryEntry;
}

export class InMemorySecureStore {
  private readonly entries: MemoryEntry[] = [];

  constructor(private readonly policy: MemoryWritePolicy) {}

  private isEntryActive(entry: MemoryEntry, now = Date.now()): boolean {
    if (!entry.expiresAt) {
      return true;
    }

    return new Date(entry.expiresAt).getTime() > now;
  }

  write(input: MemoryWriteInput): MemoryDecision {
    const now = Date.now();
    const activeEntries = this.entries.filter(
      (entry) => entry.tenantId === input.tenantId && this.isEntryActive(entry, now)
    );
    if (!this.policy.writableSources.includes(input.source)) {
      return {
        allowed: false,
        reasons: ["source_not_allowed"]
      };
    }

    if (activeEntries.length >= this.policy.maxEntriesPerTenant) {
      return {
        allowed: false,
        reasons: ["tenant_memory_budget_exceeded"]
      };
    }

    const createdAt = new Date().toISOString();
    const entry: MemoryEntry = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      capability: input.capability,
      content: input.content,
      source: input.source,
      provenance: input.provenance,
      createdAt,
      expiresAt: input.ttlSeconds
        ? new Date(Date.now() + input.ttlSeconds * 1000).toISOString()
        : undefined
    };

    this.entries.push(entry);

    return {
      allowed: true,
      reasons: ["memory_write_admitted"],
      entry
    };
  }

  listByTenant(tenantId: string): MemoryEntry[] {
    const now = Date.now();

    return this.entries.filter((entry) => {
      if (entry.tenantId !== tenantId) {
        return false;
      }

      return this.isEntryActive(entry, now);
    });
  }
}
