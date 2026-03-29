#!/usr/bin/env node
import { connectToAgent, sendTextToAgent } from "../client/connect.js";

function readArg(flag: string): string | undefined {
  const index = process.argv.indexOf(flag);
  if (index === -1) {
    return undefined;
  }

  return process.argv[index + 1];
}

function requireArg(flag: string): string {
  const value = readArg(flag);
  if (!value) {
    throw new Error(`Missing required argument ${flag}`);
  }

  return value;
}

export interface CliDependencies {
  connectToAgent: typeof connectToAgent;
  sendTextToAgent: typeof sendTextToAgent;
  log: (value: string) => void;
}

export async function runCli(
  args: string[],
  dependencies: CliDependencies = {
    connectToAgent,
    sendTextToAgent,
    log: console.log
  }
) {
  const originalArgv = process.argv;
  process.argv = [originalArgv[0] ?? "node", originalArgv[1] ?? "cli", ...args];

  try {
    const baseUrl = requireArg("--url");
    const message = requireArg("--message");
    const token = readArg("--token");
    const capability = readArg("--capability");
    const callerId = readArg("--caller") ?? "first-user";

    const connection = await dependencies.connectToAgent({
      baseUrl,
      bearerToken: token,
      callerId
    });

    const result = await dependencies.sendTextToAgent(connection, {
      message,
      capability
    });

    dependencies.log(JSON.stringify({
      agent: connection.card.name,
      description: connection.card.description,
      text: result.text
    }, null, 2));
  } finally {
    process.argv = originalArgv;
  }
}

async function main() {
  await runCli(process.argv.slice(2), {
    connectToAgent,
    sendTextToAgent,
    log: console.log
  });
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  await main();
}
