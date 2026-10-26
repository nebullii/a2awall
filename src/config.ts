import { createSecurityPolicyFromEnv, type SecurityPolicy, type SecurityPolicyEnvironment } from "./security/policy.js";

export interface RuntimeEnvironment extends SecurityPolicyEnvironment {
  port?: string;
  baseUrl?: string;
}

export interface RuntimeConfig {
  port: number;
  baseUrl: string;
  securityPolicy: SecurityPolicy;
}

function readSetting(
  environment: RuntimeEnvironment,
  camelCaseKey: keyof RuntimeEnvironment,
  uppercaseKey: string
): string | undefined {
  const value = environment[camelCaseKey];
  if (typeof value === "string" && value.length > 0) {
    return value;
  }

  const uppercaseValue = (environment as Record<string, unknown>)[uppercaseKey];
  return typeof uppercaseValue === "string" && uppercaseValue.length > 0 ? uppercaseValue : undefined;
}

export function createRuntimeConfig(environment: RuntimeEnvironment = process.env): RuntimeConfig {
  const port = Number(readSetting(environment, "port", "PORT") ?? "4000");
  const baseUrl = readSetting(environment, "baseUrl", "BASE_URL") ?? `http://localhost:${port}`;

  return {
    port,
    baseUrl,
    securityPolicy: createSecurityPolicyFromEnv({
      bearerToken: readSetting(environment, "bearerToken", "SECURITY_BEARER_TOKEN"),
      bearerTokenSha256: readSetting(environment, "bearerTokenSha256", "SECURITY_BEARER_TOKEN_SHA256"),
      principalId: readSetting(environment, "principalId", "SECURITY_PRINCIPAL_ID"),
      scopes: readSetting(environment, "scopes", "SECURITY_SCOPES"),
      allowedCapabilities: readSetting(environment, "allowedCapabilities", "SECURITY_ALLOWED_CAPABILITIES"),
      audience: readSetting(environment, "audience", "SECURITY_AUDIENCE"),
      trustTier: readSetting(environment, "trustTier", "SECURITY_TRUST_TIER")
    })
  };
}
