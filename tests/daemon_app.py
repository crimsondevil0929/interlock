"""An application for ``interlock daemon --app tests.daemon_app:build``
(``tests/test_daemon.py``): one agent that marks an order, says so, and
waits to be stopped."""

from __future__ import annotations

from interlock import BlastRadius
from interlock.config import InterlockConfig
from interlock.daemon import Application
from interlock.supervisor import AgentContext


async def mark(ctx: AgentContext) -> None:
    plan = (
        ctx.plan("agent", intent="mark an order")
        .update(
            table="orders",
            statement="UPDATE orders SET status = :s WHERE id = 500",
            parameters={"s": "seen"},
            tenant_id="acme",
            stated_rows=1,
        )
        .build()
    )
    result = await ctx.execute(plan)
    print(f"agent: plan {'committed' if result.committed else 'refused'}", flush=True)
    while await ctx.sleep(1.0):
        pass


def build(config: InterlockConfig) -> Application:
    return Application(checkers=[BlastRadius(5)], agents=[mark])


def wrong(config: InterlockConfig) -> object:
    """Not an application: what ``--app`` refuses."""
    return "an agent"
