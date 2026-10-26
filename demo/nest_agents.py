#!/usr/bin/env python3
"""
Start multiple NEST agents for A2AWall integration testing.

Each agent has a distinct role/capability and runs on its own port.
No LLM key required — agents use deterministic fallback logic.
"""
import os
import sys
import asyncio
import signal
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'NEST-beta')))

from nanda_core.core.adapter import NANDA

# ---------------------------------------------------------------------------
# Agent definitions
# ---------------------------------------------------------------------------

AGENTS = [
    {
        "id": "researcher",
        "name": "Research Agent",
        "domain": "research",
        "specialization": "information gathering and synthesis",
        "description": "Gathers and synthesizes information from multiple sources.",
        "capabilities": ["research", "summarize"],
        "port": 6001,
    },
    {
        "id": "analyst",
        "name": "Data Analyst Agent",
        "domain": "data analysis",
        "specialization": "statistical analysis and pattern recognition",
        "description": "Analyzes data patterns and produces structured insights.",
        "capabilities": ["analyze", "statistics"],
        "port": 6002,
    },
    {
        "id": "writer",
        "name": "Writer Agent",
        "domain": "content creation",
        "specialization": "clear and concise technical writing",
        "description": "Produces well-structured written content.",
        "capabilities": ["write", "edit"],
        "port": 6003,
    },
    {
        "id": "reviewer",
        "name": "Review Agent",
        "domain": "quality assurance",
        "specialization": "critical review and validation",
        "description": "Reviews work products for accuracy and completeness.",
        "capabilities": ["review", "validate"],
        "port": 6004,
    },
    {
        "id": "coordinator",
        "name": "Coordinator Agent",
        "domain": "orchestration",
        "specialization": "multi-agent task coordination",
        "description": "Coordinates work across the agent team.",
        "capabilities": ["coordinate", "delegate"],
        "port": 6005,
    },
]


def make_logic(agent_def):
    """Create deterministic agent logic (no LLM key needed)."""
    agent_id = agent_def["id"]
    agent_name = agent_def["name"]
    domain = agent_def["domain"]

    def logic(message: str, conversation_id: str, tool_runtime=None) -> str:
        msg = message.strip().lower()

        # Health / ping
        if msg in ("ping", "health", "status"):
            return json.dumps({
                "agent": agent_id,
                "status": "ok",
                "domain": domain,
                "capabilities": agent_def["capabilities"],
            })

        # Echo with identity
        if msg.startswith("echo "):
            return f"[{agent_name}] {message[5:]}"

        # Domain-specific responses
        if agent_id == "researcher":
            return (
                f"[{agent_name}] Research findings on '{message}': "
                f"Found 3 relevant sources. Key insight — the topic intersects "
                f"with distributed systems and trust frameworks."
            )
        elif agent_id == "analyst":
            return (
                f"[{agent_name}] Analysis of '{message}': "
                f"Pattern detected — 87% correlation with expected behavior. "
                f"Confidence interval: [0.82, 0.92]. Recommendation: proceed."
            )
        elif agent_id == "writer":
            return (
                f"[{agent_name}] Draft for '{message}': "
                f"## Summary\n"
                f"This document covers the key aspects of the requested topic. "
                f"The analysis shows strong alignment with project goals."
            )
        elif agent_id == "reviewer":
            return (
                f"[{agent_name}] Review of '{message}': "
                f"PASS — Content is accurate and well-structured. "
                f"Minor suggestion: add quantitative evidence in section 2."
            )
        elif agent_id == "coordinator":
            return (
                f"[{agent_name}] Coordination plan for '{message}': "
                f"Step 1: researcher gathers data. "
                f"Step 2: analyst processes findings. "
                f"Step 3: writer drafts report. "
                f"Step 4: reviewer validates output."
            )

        return f"[{agent_name}] Processed: {message}"

    return logic


async def start_agents(count=5):
    """Start `count` NEST agents (max 5)."""
    agents_to_start = AGENTS[:count]
    instances = []

    for agent_def in agents_to_start:
        logic = make_logic(agent_def)
        nanda = NANDA(
            agent_id=agent_def["id"],
            agent_logic=logic,
            agent_name=agent_def["name"],
            domain=agent_def["domain"],
            specialization=agent_def["specialization"],
            description=agent_def["description"],
            capabilities=agent_def["capabilities"],
            port=agent_def["port"],
            public_url=f"http://localhost:{agent_def['port']}",
            protocols={"a2a": {"enabled": True}},
            enable_telemetry=False,
        )
        instances.append((agent_def, nanda))

    # Print agent manifest for the gateway to consume
    manifest = []
    for agent_def, _ in instances:
        manifest.append({
            "id": agent_def["id"],
            "name": agent_def["name"],
            "url": f"http://localhost:{agent_def['port']}",
            "capabilities": agent_def["capabilities"],
            "port": agent_def["port"],
        })
    print(f"NEST_MANIFEST={json.dumps(manifest)}")
    sys.stdout.flush()

    # Start all agents concurrently
    print(f"\nStarting {len(instances)} NEST agents...")
    tasks = []
    for agent_def, nanda in instances:
        print(f"  -> {agent_def['name']} ({agent_def['id']}) on port {agent_def['port']}")
        tasks.append(asyncio.create_task(nanda.start()))

    # Wait for interrupt
    stop = asyncio.Event()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    print(f"\nAll {len(instances)} NEST agents running. Press Ctrl+C to stop.\n")
    await stop.wait()

    print("\nShutting down agents...")
    for task in tasks:
        task.cancel()


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    asyncio.run(start_agents(count))
