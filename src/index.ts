import { createApp } from "./app.js";
import { createRuntimeConfig } from "./config.js";

const runtimeConfig = createRuntimeConfig({
  port: process.env.PORT,
  baseUrl: process.env.BASE_URL,
  bearerToken: process.env.SECURITY_BEARER_TOKEN,
  bearerTokenSha256: process.env.SECURITY_BEARER_TOKEN_SHA256,
  principalId: process.env.SECURITY_PRINCIPAL_ID,
  scopes: process.env.SECURITY_SCOPES,
  allowedCapabilities: process.env.SECURITY_ALLOWED_CAPABILITIES,
  audience: process.env.SECURITY_AUDIENCE,
  trustTier: process.env.SECURITY_TRUST_TIER
});

const app = createApp({
  baseUrl: runtimeConfig.baseUrl,
  securityPolicy: runtimeConfig.securityPolicy
});

app.listen(runtimeConfig.port, () => {
  console.log(`A2A starter listening on ${runtimeConfig.baseUrl}`);
  console.log(`Agent Card: ${runtimeConfig.baseUrl}/.well-known/agent-card.json`);
  console.log(`JSON-RPC: ${runtimeConfig.baseUrl}/a2a/jsonrpc`);
  console.log(`REST: ${runtimeConfig.baseUrl}/a2a/rest`);
  console.log(
    `Use Authorization: Bearer <configured-token> and ${runtimeConfig.securityPolicy.metadata.capabilityHeader}: ${Object.keys(runtimeConfig.securityPolicy.capabilityPolicies)[0] ?? "echo"}`
  );
});
