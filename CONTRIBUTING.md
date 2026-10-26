# Contributing

A2AWall is a small, single-maintainer project. Keep changes focused and reviewable.

For suspected vulnerabilities, do not open an issue or pull request. Follow
[SECURITY.md](SECURITY.md).

## Development Setup

Node.js 20 or later.

```bash
npm install
npm run build
npm test
```

`npm test` runs the build first, so a type error fails the test run.

To run the server locally:

```bash
cp .env.example .env
npm start
```

## Tests

Tests live in two entrypoints, and `npm test` runs both. There is no test framework.

`src/test.ts` holds the unit and in-process tests. The file
imports `node:assert/strict`, defines one async function per area, and calls each one at the
bottom. It compiles to `dist/test.js` and runs as `node dist/test.js`, or `npm run test:unit`.

`src/e2e.ts` boots the built `dist/index.js` as a subprocess and drives it over HTTP with
the real A2A client, the real CLI binary, and raw requests on both the JSON-RPC and REST
bindings. Run it with `npm run test:e2e`.

Put a check in `src/e2e.ts` when it depends on the wire format, the transport binding, or
process startup. The two bindings use different wire formats for the same message: the
JSON-RPC binding nests the message under `params` and names its parts `parts`, while the
REST binding decodes proto-JSON, puts the message at the top level, names its parts
`content`, and omits the `kind` discriminator. An admission check written against one shape
silently passes everything on the other, and only an over-the-wire test catches it. Every
REST check in that file is deliberately paired with a JSON-RPC counterpart.

To add a test:

1. Add an async function in `src/test.ts` near the related ones.
2. Add an `await` call for it in the list at the bottom of the file.
3. Run `npm test`. A passing run prints `tests passed` and nothing else.

Keep tests deterministic. No network calls, no real clocks, no fixed ports that could
already be bound.

### Negative-path tests are required

Every security-relevant change must add at least one test that asserts a request is
rejected. A test that only shows the allowed path passes does not show the control works.

A security-relevant change is anything touching `src/security/`, `src/context/`,
`src/runtime/`, `src/validation/`, `src/memory/`, `src/retrieval/`, or
`src/orchestration/`, and any change to the agent card's security fields or to policy
defaults.

The negative test asserts the rejection, not just the absence of success. Depending on the
layer that means asserting the status code, that the next handler was never called, or that
the evaluator returned a deny with the expected reason:

```ts
assert.equal(response.statusCode, 403);
assert.equal(nextCalled, false);
assert.equal(decision.allowed, false);
assert.deepEqual(decision.reasons, ["capability_not_granted"]);
```

If you widen what is permitted, say so in the pull request and show which existing negative
test still holds.

## Pull Requests

- `npm run build` must be clean. `tsconfig.json` sets `strict`, and that is not negotiable.
  No `any` to get past the compiler, no `@ts-ignore`, no `@ts-expect-error` without a
  comment saying what it is waiting on.
- `npm test` must pass.
- One concern per pull request. Do not mix a refactor with a behaviour change.
- Do not edit `dist/`. It is build output.
- If you change a documented default or a policy field, update the affected file under
  `docs/` in the same pull request. `src/test.ts` asserts on the contents of the docs pages.
- Say what you tested and what you did not.

## Commit Style

Short imperative subject line, capitalized, no trailing period, under about 70 characters.

```
Reject delegation past the configured fan-out limit
Add negative test for unknown capability admission
```

No prefixes or tags in the subject. Put context in the body if the subject is not enough,
wrapped at 72 characters. One logical change per commit.
