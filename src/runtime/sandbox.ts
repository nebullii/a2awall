import { isIP } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
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

/**
 * Operations permitted by each access mode. `bounded-write` deliberately excludes
 * `execute`: arbitrary execution is only available to `privileged` capabilities.
 */
const OPERATIONS_BY_ACCESS_MODE: Record<ToolAccessMode, ToolOperation[]> = {
  none: [],
  "read-only": ["read"],
  "bounded-write": ["read", "write"],
  privileged: ["read", "write", "execute"]
};

const ALLOWED_URL_PROTOCOLS = new Set(["http:", "https:"]);

function deny(reason: string, statusCode: number, message: string): SandboxDecision {
  return { allowed: false, reasons: [reason], statusCode, message };
}

function normalizeHost(hostname: string): string {
  let host = hostname.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }
  if (host.endsWith(".") && host.length > 1) {
    host = host.slice(0, -1);
  }

  return host;
}

function ipv4ToLong(address: string): number | undefined {
  const octets = address.split(".");
  if (octets.length !== 4) {
    return undefined;
  }

  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) {
      return undefined;
    }

    const parsed = Number(octet);
    if (parsed > 255) {
      return undefined;
    }

    value = value * 256 + parsed;
  }

  return value;
}

/**
 * Blocks loopback, unspecified, private, shared-address-space, link-local
 * (including the cloud instance metadata range 169.254.0.0/16), benchmarking,
 * documentation, multicast and reserved IPv4 space.
 */
function isBlockedIpv4(address: string): boolean {
  const value = ipv4ToLong(address);
  if (value === undefined) {
    return true;
  }

  const inRange = (cidrBase: string, prefixLength: number): boolean => {
    const base = ipv4ToLong(cidrBase);
    if (base === undefined) {
      return false;
    }

    const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
    return (value & mask) === (base & mask);
  };

  return (
    inRange("0.0.0.0", 8) ||
    inRange("10.0.0.0", 8) ||
    inRange("100.64.0.0", 10) ||
    inRange("127.0.0.0", 8) ||
    inRange("169.254.0.0", 16) ||
    inRange("172.16.0.0", 12) ||
    inRange("192.0.0.0", 24) ||
    inRange("192.0.2.0", 24) ||
    inRange("192.168.0.0", 16) ||
    inRange("198.18.0.0", 15) ||
    inRange("198.51.100.0", 24) ||
    inRange("203.0.113.0", 24) ||
    inRange("224.0.0.0", 4) ||
    inRange("240.0.0.0", 4)
  );
}

/**
 * Blocks the IPv6 equivalents, plus IPv4-mapped and NAT64-embedded addresses
 * that would otherwise smuggle a blocked IPv4 target past the check.
 */
function isBlockedIpv6(address: string): boolean {
  const host = address.toLowerCase().split("%")[0] ?? "";
  if (host === "::" || host === "::1") {
    return true;
  }

  const embeddedIpv4 = host.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (embeddedIpv4?.[1]) {
    return isBlockedIpv4(embeddedIpv4[1]);
  }

  const hextets = host.split(":").filter(Boolean);
  const first = hextets[0] ?? "";
  if (/^f[cd]/.test(first)) {
    return true;
  }
  if (/^fe[89ab]/.test(first)) {
    return true;
  }
  if (/^ff/.test(first)) {
    return true;
  }
  if (host.startsWith("64:ff9b:")) {
    return true;
  }

  return false;
}

function isBlockedIpLiteral(host: string): boolean {
  const version = isIP(host);
  if (version === 4) {
    return isBlockedIpv4(host);
  }
  if (version === 6) {
    return isBlockedIpv6(host);
  }

  return false;
}

function hostMatchesAllowlist(host: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((entry) => {
    const candidate = normalizeHost(entry);
    if (candidate.startsWith("*.")) {
      const suffix = candidate.slice(1);
      return host.endsWith(suffix) && host.length > suffix.length;
    }

    return host === candidate;
  });
}

/**
 * Lexical egress check. A hostname that resolves to a blocked address at
 * connect time is not detectable here: the HTTP client performing the request
 * must also validate the resolved address to close DNS rebinding.
 */
function evaluateNetworkTarget(
  target: string | undefined,
  allowedDomains: string[] | undefined
): SandboxDecision | undefined {
  if (!target) {
    return deny("target_required", 400, "Network tool invocations must declare a target URL.");
  }

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return deny("target_not_a_url", 400, "Network target is not a valid absolute URL.");
  }

  if (!ALLOWED_URL_PROTOCOLS.has(url.protocol)) {
    return deny("scheme_not_allowed", 403, `Network scheme '${url.protocol}' is not allowed.`);
  }

  if (url.username || url.password) {
    return deny("url_credentials_not_allowed", 403, "Network target must not embed credentials.");
  }

  const host = normalizeHost(url.hostname);
  if (!host) {
    return deny("target_not_a_url", 400, "Network target has no host.");
  }

  if (isBlockedIpLiteral(host)) {
    return deny(
      "internal_address_blocked",
      403,
      "Network target resolves to a loopback, private, or link-local address."
    );
  }

  if (!allowedDomains || allowedDomains.length === 0) {
    return deny(
      "no_domain_allowlist",
      403,
      "No network allowlist is configured, so all network egress is denied."
    );
  }

  if (!hostMatchesAllowlist(host, allowedDomains)) {
    return deny("domain_not_allowed", 403, "Network target is outside the sandbox allowlist.");
  }

  return undefined;
}

/**
 * Lexical path check. Symlinks are not resolved here: a tool that opens paths
 * must resolve the real path before use.
 */
function evaluateFilesystemTarget(
  target: string | undefined,
  prefixes: string[] | undefined
): SandboxDecision | undefined {
  if (!target) {
    return deny("target_required", 400, "Filesystem tool invocations must declare a target path.");
  }

  if (target.includes("\0")) {
    return deny("invalid_path", 400, "Filesystem target contains a null byte.");
  }

  if (!isAbsolute(target)) {
    return deny("path_must_be_absolute", 400, "Filesystem target must be an absolute path.");
  }

  if (!prefixes || prefixes.length === 0) {
    return deny(
      "no_path_allowlist",
      403,
      "No filesystem allowlist is configured, so all filesystem access is denied."
    );
  }

  const resolved = resolve(target);
  const withinPrefix = prefixes.some((prefix) => {
    const resolvedPrefix = resolve(prefix);
    if (resolved === resolvedPrefix) {
      return true;
    }

    const boundary = resolvedPrefix.endsWith(sep) ? resolvedPrefix : `${resolvedPrefix}${sep}`;
    return resolved.startsWith(boundary);
  });

  if (!withinPrefix) {
    return deny("path_not_allowed", 403, "Filesystem target is outside the sandbox allowlist.");
  }

  return undefined;
}

export function evaluateToolInvocation(
  policy: SandboxPolicy,
  tool: ToolDefinition,
  request: ToolInvocationRequest
): SandboxDecision {
  if (request.toolId !== tool.id) {
    return deny(
      "tool_identity_mismatch",
      400,
      `Requested tool '${request.toolId}' does not match resolved tool '${tool.id}'.`
    );
  }

  if (policy.toolAccess === "none") {
    return deny(
      "tool_access_disabled",
      403,
      `Capability '${policy.capability}' cannot invoke tools.`
    );
  }

  if (!policy.allowedToolIds.includes(tool.id)) {
    return deny(
      "tool_not_allowed",
      403,
      `Tool '${tool.id}' is not allowed for capability '${policy.capability}'.`
    );
  }

  if (!tool.operations.includes(request.operation)) {
    return deny(
      "operation_not_supported",
      400,
      `Tool '${tool.id}' does not support '${request.operation}'.`
    );
  }

  if (!OPERATIONS_BY_ACCESS_MODE[policy.toolAccess].includes(request.operation)) {
    return deny(
      "operation_not_permitted",
      403,
      `Capability '${policy.capability}' has '${policy.toolAccess}' tool access and cannot perform '${request.operation}'.`
    );
  }

  if (policy.maxToolCalls <= 0) {
    return deny(
      "tool_budget_exhausted",
      403,
      `Capability '${policy.capability}' has no tool call budget.`
    );
  }

  if (request.toolCallCount >= policy.maxToolCalls) {
    return deny(
      "tool_budget_exceeded",
      429,
      `Tool call budget exceeded for capability '${policy.capability}'.`
    );
  }

  if (tool.kind === "network") {
    const networkDecision = evaluateNetworkTarget(
      request.target,
      policy.networkDomains ?? tool.allowedDomains
    );
    if (networkDecision) {
      return networkDecision;
    }
  }

  if (tool.kind === "filesystem") {
    const filesystemDecision = evaluateFilesystemTarget(
      request.target,
      policy.filesystemPrefixes ?? tool.allowedPaths
    );
    if (filesystemDecision) {
      return filesystemDecision;
    }
  }

  return {
    allowed: true,
    reasons: ["sandbox_admitted"]
  };
}
