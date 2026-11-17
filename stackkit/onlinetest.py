"""The client half of the online tests (python -m stackkit.control test / grade).

The gateway hands out a plan for each test; this module runs it on the
student's stack and returns the outcome, which goes back to the gateway for the
verdict. The runner never knows what a test checks. Plan kinds:
    tcp   -- the generic TCP client (stackkit.tcptest)
    idle  -- keep the stack running for duration_ms, answering what arrives
    ping  -- count echo requests to dst (size bytes of data each)
    app   -- the student's app client (paderstack.appclient.run_app) over the
             student's stack, against a test session of the app server
An error the stack raises (an unimplemented stub, say) goes into the outcome.
"""

from __future__ import annotations

import importlib
import time
from typing import Any

from stackkit.tcptest import TcpTestClient


class PlanError(Exception):
    """A plan this framework cannot run (the course package needs an update)."""


def run_plan(runtime: Any, plan: dict[str, Any], config: Any = None) -> dict[str, Any]:
    """Run one plan on the runtime's stack and return its outcome (config: student.toml)."""
    kind = plan.get("kind", "tcp")
    if kind == "tcp":
        return _run_tcp(runtime, plan)
    if kind == "idle":  # the stack answers ARP and pings on its own meanwhile
        time.sleep(int(plan["duration_ms"]) / 1000)
        return {"error": _stack_error(runtime)}
    if kind == "ping":
        return _run_ping(runtime, plan)
    if kind == "app":
        return _run_app(runtime, plan, config)
    raise PlanError(f"unknown test plan {kind!r}: please update your course package")


def _stack_error(runtime: Any) -> str | None:
    """The first error the stack raised on its own thread, as text."""
    if not runtime.errors:
        return None
    first = runtime.errors[0].exception
    return f"{type(first).__name__}: {first}"


def _run_ping(runtime: Any, plan: dict[str, Any]) -> dict[str, Any]:
    """The ping plan: count echo requests to dst, reported as sent and received."""
    from stackkit.ping import ping

    # the echo data: size bytes counting up, the same on every run
    payload = bytes(i % 256 for i in range(int(plan["size"])))
    try:
        stats = ping(
            runtime,
            str(plan["dst"]),
            count=int(plan["count"]),
            timeout_ms=int(plan["timeout_ms"]),
            payload=payload,
        )
    except (NotImplementedError, OSError) as exc:
        # no echo interface or an unimplemented stub: nothing went out, the error says why
        return {"sent": 0, "received": 0, "error": f"{type(exc).__name__}: {exc}"}
    return {"sent": stats.sent, "received": stats.received, "error": _stack_error(runtime)}


def _run_app(runtime: Any, plan: dict[str, Any], config: Any) -> dict[str, Any]:
    """The app plan: paderstack.appclient over the stack; the outcome is its completion code."""
    # looked up by name: the framework has no import of the student package
    sockets = importlib.import_module("paderstack.socket")
    run_app = importlib.import_module("paderstack.appclient").run_app
    try:
        code = run_app(
            sockets.bound_module(runtime),
            server_ip=str(plan["server_ip"]),
            control_port=int(plan["port"]),
            student_index=config.student_index,
            proto_key=config.keys.proto_key,
            timeout_s=float(plan["timeout_s"]),
            hello_request=str(plan["hello"]),
        )
    except Exception as exc:  # noqa: BLE001 - the verdict says what went wrong
        return {"code": None, "error": _stack_error(runtime) or f"{type(exc).__name__}: {exc}"}
    return {"code": code, "error": None}


def _run_tcp(runtime: Any, plan: dict[str, Any]) -> dict[str, Any]:
    """The tcp plan: poll a TcpTestClient on the stack thread every 20 ms until it is done."""
    stack = runtime.stack
    now = runtime.clock.now_ms()
    agent = runtime.run_in_stack(lambda: TcpTestClient(stack, plan, now)).result()
    while True:  # each poll runs on the stack thread; the sleep keeps this thread off it
        outcome: dict[str, Any] | None = runtime.run_in_stack(
            lambda: agent.step(runtime.clock.now_ms())
        ).result()
        if outcome is not None:
            return outcome
        time.sleep(0.02)
