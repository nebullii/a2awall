# A2AWall

Reusable TypeScript package for exposing agents over standard A2A while enforcing a stronger gateway security layer.

What is implemented now:

- A2A-compatible Agent Card and transports
- gateway admission control
- bearer-token auth
- scope and capability checks
- trust-tier checks
- approval-gate support
- message-size limits
- risk and tool-access metadata
- trusted-context boundary helpers

What is not fully implemented yet:

- sandboxed tool execution
- memory security backend
- retrieval provenance enforcement
- multi-agent delegation control plane

Use this repo when you want baseline A2A interoperability plus your own security controls at the adapter or gateway layer.

## Start Here

- User guide: [USER_GUIDE.md](/Users/nehachaudhari/Developer/a2awall/USER_GUIDE.md)
- Security roadmap: [SECURITY_ROADMAP.md](/Users/nehachaudhari/Developer/a2awall/SECURITY_ROADMAP.md)
- GitHub Pages docs: publish the [`docs/`](/Users/nehachaudhari/Developer/a2awall/docs) folder

## Quick Start

```bash
npm install
cp .env.example .env
npm test
npm run build
npm start
```

## Package Use

Install locally in this repo:

```bash
npm install
```

If you later publish it:

```bash
npm install a2awall
```

## CLI

```bash
npm run build
npm run connect -- --url http://localhost:4000 --token dev-token --caller first-user --capability echo --message "hello secure a2a"
```

If installed as a package:

```bash
a2awall-connect --url http://localhost:4000 --token dev-token --caller first-user --capability echo --message "hello secure a2a"
```

## Verification

```bash
npm test
node dist/smoke.js
```
