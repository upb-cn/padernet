"""Command-line access to the course gateway: status, scenarios, reset, ping, tests, grades.

Usage (from the course package directory, next to student.toml):
    python -m stackkit.control test --list          # every milestone's tests
    python -m stackkit.control test m2              # all public tests of milestone 2
    python -m stackkit.control test handshake       # one public test
    python -m stackkit.control test slow-start --trace   # ... and print the cc trace
    python -m stackkit.control grade m2             # the graded test of milestone 2
    python -m stackkit.control grade --status       # your graded results
    python -m stackkit.control status [--json]
    python -m stackkit.control scenario --list
    python -m stackkit.control scenario loss
    python -m stackkit.control reset
    python -m stackkit.control ping 10.128.37.3 [--count 3]

Options before the command: --config PATH (default student.toml) and, for
ping, test, grade and tcp-test, --stack MODULE:CLASS (default
paderstack.host:PaderStack).

ping, test, grade and tcp-test write a debugging log, padernet.log next to
student.toml, truncated at every run: every logging record of your code
(logging.getLogger(__name__).info(...)) and the framework's own events, one
line each, stamped with your stack's clock in milliseconds.

Run this while your own program is NOT connected: every process opens its own
tunnel session, and the gateway follows the newest one, so a CLI call in the
middle of a running program steals its session. Inside a running program, use
Runtime.control(...) instead.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from stackkit.config import ConfigError, StudentConfig, load_student_config
from stackkit.log import FILE_NAME, close_log, open_log, section
from stackkit.onlinetest import PlanError
from stackkit.tunnel_client import TunnelClient, TunnelClientError

MILESTONES = ("m1", "m2", "m3")


def _client(config: StudentConfig) -> TunnelClient:
    """A tunnel client for the gateway named in student.toml."""
    return TunnelClient(
        config.network.gateway_host,
        config.network.gateway_port,
        config.student_index,
        config.keys.tunnel_key,
    )


def _request(config: StudentConfig, op: str, **params: Any) -> dict[str, Any]:
    """One control request in a short session of its own; for use when no runtime is running."""
    with _client(config) as client:  # single-threaded: no runtime is running here
        client.attach()
        return client.request(op, **params)


def _load_stack(spec: str) -> Any:
    """Import the stack class that --stack names as module:Class."""
    module_name, _, class_name = spec.partition(":")
    if not module_name or not class_name:
        raise ValueError(f"--stack must look like module:Class, got {spec!r}")
    return getattr(importlib.import_module(module_name), class_name)


def _cmd_ping(config: StudentConfig, args: argparse.Namespace) -> int:
    """ping: send ICMP echoes through the student stack; exit 0 only if every reply came back."""
    from stackkit.ping import ping
    from stackkit.runtime import Runtime

    section(f"ping {args.ip}: stack started")
    with Runtime(config, _load_stack(args.stack), client=_client(config)) as runtime:
        stats = ping(runtime, args.ip, count=args.count, timeout_ms=args.timeout_ms)
    section(f"ping {args.ip}: {stats.received} of {stats.sent} replies")
    for reply in stats.replies:
        print(f"{reply.nbytes} bytes from {reply.src_ip}: seq={reply.seq} time={reply.rtt_ms} ms")
    print(f"--- {args.ip}: {stats.sent} sent, {stats.received} received ---")
    return 0 if stats.received == stats.sent else 1


def _cmd_scenario_list(config: StudentConfig) -> int:
    """scenario --list: the current scenario and every one the gateway offers."""
    reply = _request(config, "scenario_list")
    if not reply.get("ok"):
        print(f"error: {reply.get('error')}", file=sys.stderr)
        return 1
    print(f"current scenario: {reply['current']}")
    print("scenarios (link conditions toward the servers, unlimited):")
    for sc in reply["scenarios"]:
        if not sc["graded"]:
            print(f"  {sc['name']:<15} {sc['conditions']}")
    graded = [sc for sc in reply["scenarios"] if sc["graded"]]
    if graded:  # the gateway lists none since graded tests switch their scenario themselves
        print("graded scenarios (fixed loss pattern, limited entries):")
        for sc in graded:
            print(f"  {sc['name']:<15} {sc['conditions']}  [{sc['entries_left']} entries left]")
    return 0


def _cmd_scenario(config: StudentConfig, name: str) -> int:
    """scenario NAME: switch the link conditions toward the servers; one line says what is on."""
    reply = _request(config, "set_scenario", scenario=name)
    if not reply.get("ok"):
        if reply.get("error") == "unknown_scenario":
            print(f"error: unknown scenario {name!r}; scenario --list shows them", file=sys.stderr)
        else:
            print(f"error: {reply.get('error')}", file=sys.stderr)
        return 1
    conditions = reply.get("conditions")  # the gateway describes the scenario's link conditions
    detail = f": {conditions}" if conditions else ""
    print(f"scenario switched to {reply.get('scenario', name)}{detail}")
    return 0


def _cmd_reset(config: StudentConfig) -> int:
    """reset: clear the gateway-side state of this student; one line confirms it."""
    reply = _request(config, "reset")
    if not reply.get("ok"):
        print(f"error: {reply.get('error')}", file=sys.stderr)
        return 1
    print(
        "gateway-side state cleared: ARP cache, pending resolutions, impairment channels, "
        "armed tests (the scenario and the counters stay)"
    )
    return 0


def _print_verdict(verdict: dict[str, Any]) -> None:
    """Print a test verdict: one line per step, then PASSED or FAILED."""
    for step in verdict.get("steps", []):
        mark = "OK  " if step["ok"] else "FAIL"
        count = f" (x{step['count']})" if step.get("count") else ""
        detail = f" -- {step['detail']}" if step.get("detail") else ""
        print(f"  [{mark}] {step['step']}{count}{detail}")
    result = "PASSED" if verdict.get("passed") else "FAILED"
    print(f"{verdict.get('test')}: {result}")


def _local_time(iso: str | None) -> str:
    """A deadline in the local time zone (display only)."""
    if iso is None:
        return "no deadline"
    from datetime import datetime

    return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M %Z")


def _cmd_test_list(config: StudentConfig) -> int:
    """test --list: every milestone's public tests and the state of its graded test."""
    with _client(config) as client:
        client.attach()
        replies = [client.request("test_list", milestone=m) for m in MILESTONES]
    for reply in replies:
        if not reply.get("ok"):
            print(f"error: {reply.get('error')}", file=sys.stderr)
            return 1
        graded = reply["graded"]
        print(f"{reply['milestone']}:")
        if not reply["public"]:
            print("  (no online tests yet)")
            continue
        for name, summary in reply["public"]:
            print(f"  {name:<20} {summary}")
        state = "open" if graded["open"] else "closed"
        print(
            f"  graded: grade {reply['milestone']} -- {graded['components']} components, "
            f"{graded['attempts_left']} attempts left, {state}, "
            f"deadline {_local_time(graded['deadline'])}"
        )
    return 0


def _with_fresh_stack(
    config: StudentConfig, args: argparse.Namespace, body: Any, tracer: Any = None
) -> Any:
    """Run body(runtime) on a new stack (so no test inherits an ARP cache or a connection)."""
    from stackkit.runtime import Runtime

    with Runtime(config, _load_stack(args.stack), client=_client(config), tracer=tracer) as runtime:
        return body(runtime)


class _TraceClock:
    """The runtime's clock for a tracer that is created before the runtime (bound in body)."""

    def __init__(self) -> None:
        """Unbound at first; the test body binds the runtime once it exists."""
        self.runtime: Any = None  # set by the test body once the runtime exists

    def now_ms(self) -> int:
        """The runtime's clock, or 0 before it is bound."""
        return int(self.runtime.clock.now_ms()) if self.runtime is not None else 0

    def call_later(self, delay_ms: int, cb: Any) -> Any:  # the Clock protocol; unused here
        """Delegates to the runtime's clock; the tracer never schedules anything."""
        return self.runtime.clock.call_later(delay_ms, cb)


def _print_stack_error(first: Any) -> None:
    """The first error the stack raised while handling packets, on stderr."""
    if isinstance(first.exception, NotImplementedError):
        print(f"your stack does not implement this yet: {first.exception}", file=sys.stderr)
        return
    print(f"your stack raised an error in {first.where}:", file=sys.stderr)
    print(first.traceback_text, file=sys.stderr, end="")


def _print_cc_trace(records: list[Any]) -> None:
    """The cc trace channel of one test: the state after every change, with its cause."""
    if not records:
        print("cc trace: no records (Reno reported no change of cwnd or ssthresh)")
        return
    print("cc trace (bytes):")
    print(f"  {'t_ms':>7}  {'event':<15}{'cwnd':>8}{'ssthresh':>10}{'flight':>8}")
    for record in records:
        f = record.fields
        event, cwnd, ssthresh, flight = (
            str(f.get(k, "")) for k in ("event", "cwnd", "ssthresh", "flight")
        )
        print(f"  {record.t_ms:>7}  {event:<15}{cwnd:>8}{ssthresh:>10}{flight:>8}")


def _cmd_test(config: StudentConfig, args: argparse.Namespace) -> int:
    """test NAME: run one public test, or all of a milestone; exit 0 only if every one passed."""
    from stackkit.onlinetest import run_plan

    if args.name in MILESTONES:  # a milestone: every public test it lists
        listing = _request(config, "test_list", milestone=args.name)
        if not listing.get("ok"):
            print(f"error: {listing.get('error')}", file=sys.stderr)
            return 1
        names = [name for name, _summary in listing["public"]]
    else:
        names = [args.name]

    def one_test(name: str) -> tuple[Any, Any]:
        """Run one test on a fresh stack; returns its verdict and the tracer, if any."""
        tracer = clock = None
        if args.trace:  # record the cc channel (Reno's cwnd and ssthresh after every change)
            from stackkit.trace import RecordingTracer

            clock = _TraceClock()
            tracer = RecordingTracer(clock)

        def body(runtime: Any) -> dict[str, Any]:
            """The test on the runtime: start it, run the plan, report the outcome."""
            if clock is not None:
                clock.runtime = runtime
            start: dict[str, Any] = runtime.control("test_start", test=name)
            if not start.get("ok"):
                return start
            outcome = run_plan(runtime, start["plan"], config)
            verdict: dict[str, Any] = runtime.control("test_report", test=name, outcome=outcome)
            if runtime.errors:  # the stack raised on its own thread: show the first error
                verdict["stack_error"] = runtime.errors[0]
            return verdict

        section(f"{name}: stack started")
        return _with_fresh_stack(config, args, body, tracer), tracer

    failed = 0
    for name in names:
        verdict, tracer = one_test(name)
        if not verdict.get("ok"):
            section(f"{name}: error {verdict.get('error')}")
            print(f"error: {verdict.get('error')}", file=sys.stderr)
            return 1
        section(f"{name}: {'passed' if verdict.get('passed') else 'FAILED'}")
        _print_verdict(verdict)
        if tracer is not None:
            _print_cc_trace(tracer.channel("cc"))
        if not verdict.get("passed") and "stack_error" in verdict:
            _print_stack_error(verdict["stack_error"])
        failed += not verdict.get("passed")
    if len(names) > 1:
        print(f"{len(names) - failed} of {len(names)} tests passed")
    return 1 if failed else 0


def _cmd_grade_status(config: StudentConfig) -> int:
    """grade --status: best score, attempts left and deadline of every milestone."""
    reply = _request(config, "grade_status")
    if not reply.get("ok"):
        print(f"error: {reply.get('error')}", file=sys.stderr)
        return 1
    for milestone, entry in reply["milestones"].items():
        best = "-" if entry["best"] is None else f"{entry['best']:g}"
        state = "open" if entry["open"] else "closed"
        print(
            f"{milestone}: best {best} of {entry['points']} points, "
            f"{entry['attempts_left']} attempts left, {state}, "
            f"deadline {_local_time(entry['deadline'])}"
        )
    return 0


def _cmd_grade(config: StudentConfig, args: argparse.Namespace, argv: list[str]) -> int:
    """grade MILESTONE: run the graded test component by component, each on a fresh stack."""
    from stackkit.onlinetest import run_plan

    if args.milestone not in MILESTONES:
        print(f"error: unknown milestone {args.milestone!r} (one of {', '.join(MILESTONES)})")
        return 1
    if not args.yes:  # an attempt is consumed: confirm first
        answer = input(f"The graded test of {args.milestone} uses one of your attempts. Go? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("cancelled")
            return 1

    milestone = args.milestone
    _open_log(args, argv)  # after the confirmation: a cancelled run keeps the last log
    start = _request(config, "grade_start", milestone=milestone)
    if not start.get("ok"):
        print(f"error: {start.get('error')}", file=sys.stderr)
        return 1
    attempt, left = start["attempt"], start["attempts_left"]
    print(f"graded test {milestone}, attempt {attempt} ({left} left)")

    def component(runtime: Any) -> dict[str, Any]:
        """One component on the runtime; the step alone when the gateway says done or fails."""
        step = runtime.control("grade_next", milestone=milestone)
        if not step.get("ok") or step.get("done"):
            return {"step": step}
        section(f"{milestone} {step['component']}: started")
        outcome = run_plan(runtime, step["plan"], config)
        verdict = runtime.control(
            "grade_report", milestone=milestone, component=step["component"], outcome=outcome
        )
        return {"step": step, "verdict": verdict}

    result: dict[str, Any] = {}
    while True:
        done = _with_fresh_stack(config, args, component)
        step, verdict = done["step"], done.get("verdict")
        if not step.get("ok"):
            print(f"error: {step.get('error')}", file=sys.stderr)
            return 1
        if verdict is None:  # grade_next said done: nothing left, it reports the result itself
            result = step if "components" in step else result
            break
        if not verdict.get("ok"):
            print(f"error: {verdict.get('error')}", file=sys.stderr)
            return 1
        if verdict.get("retry"):  # a failed component runs once more, same parameters
            section(f"{milestone} {verdict['component']}: failed, running it once more")
            print(f"  {verdict['component']:<20} failed, running it once more")
            continue
        section(
            f"{milestone} {verdict['component']}: {'passed' if verdict['passed'] else 'FAILED'}"
        )
        print(f"  {verdict['component']:<20} {'passed' if verdict['passed'] else 'FAILED'}")
        if verdict.get("done"):
            result = verdict
            break
    components = result.get("components", {})
    passed = sum(components.values())
    print(
        f"{milestone}: {passed} of {len(components)} components passed, "
        f"score {result.get('score', 0):g}"
    )
    return 0 if components and passed == len(components) else 1


def main(argv: list[str] | None = None) -> int:
    """Parse the command line, run the command and return the exit status."""
    parser = argparse.ArgumentParser(
        prog="python -m stackkit.control",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", default="student.toml", help="path to student.toml")
    parser.add_argument(
        "--stack",
        default="paderstack.host:PaderStack",
        help="stack class for ping, test, grade and tcp-test, as module:Class",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    status_parser = sub.add_parser("status", help="link statistics and the gateway's drops")
    status_parser.add_argument("--json", action="store_true", help="print the raw reply")
    scenario = sub.add_parser("scenario", help="switch the gateway scenario")
    scenario.add_argument("name", nargs="?", help="scenario to switch to (see --list)")
    scenario.add_argument("--list", action="store_true", help="list the scenarios")
    sub.add_parser("reset", help="clear gateway-side connection state and ARP cache")
    ping_parser = sub.add_parser("ping", help="ping an address through your own stack")
    ping_parser.add_argument("ip")
    ping_parser.add_argument("--count", type=int, default=3)
    ping_parser.add_argument("--timeout-ms", type=int, default=1000)
    test_parser = sub.add_parser("test", help="run public online tests (unlimited, not graded)")
    test_parser.add_argument("name", nargs="?", help="a test, or a milestone (m1..m3) for all")
    test_parser.add_argument("--list", action="store_true", help="list every milestone's tests")
    test_parser.add_argument(
        "--trace", action="store_true", help="print the cc trace (Reno's cwnd trajectory) after"
    )
    grade_parser = sub.add_parser("grade", help="run a milestone's graded test (limited)")
    grade_parser.add_argument("milestone", nargs="?", help="m1, m2 or m3")
    grade_parser.add_argument("--status", action="store_true", help="your graded results")
    grade_parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    tcp_parser = sub.add_parser("tcp-test", help="the former name of test")
    tcp_parser.add_argument("name", nargs="?", help="test to run (see --list)")
    tcp_parser.add_argument("--list", action="store_true", help="list the available tests")
    tcp_parser.add_argument("--trace", action="store_true", help="print the cc trace after")
    args = parser.parse_args(argv)
    try:
        return _run_command(args, argv if argv is not None else sys.argv[1:])
    finally:
        close_log()


def _runs_the_stack(args: argparse.Namespace) -> bool:
    """Whether the command creates a runtime (and so gets the debugging log)."""
    if args.command == "ping":
        return True
    if args.command in ("test", "tcp-test"):
        return args.name is not None and not args.list
    return False  # grade opens the log itself, after its confirmation


def _open_log(args: argparse.Namespace, argv: list[str]) -> None:
    """padernet.log next to student.toml, headed by the command and the local time."""
    started = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    open_log(
        Path(args.config).parent / FILE_NAME,
        f"# python -m stackkit.control {' '.join(argv)}   {started}",
    )


def _run_command(args: argparse.Namespace, argv: list[str]) -> int:
    """Run the parsed command; argv is the command line, for the log's header."""
    try:
        config = load_student_config(args.config)
        if _runs_the_stack(args):
            _open_log(args, argv)
        if args.command == "ping":
            return _cmd_ping(config, args)
        if args.command == "status" and not args.json:  # the formatted view; --json is below
            from stackkit.statusview import format_status

            reply = _request(config, "status")
            print(format_status(reply, wall_now=time.time()))  # display only: local drop times
            return 0 if reply.get("ok", False) else 1
        if args.command == "test":
            if args.list or args.name is None:
                return _cmd_test_list(config)
            return _cmd_test(config, args)
        if args.command == "grade":
            if args.status or args.milestone is None:
                return _cmd_grade_status(config)
            return _cmd_grade(config, args, argv)
        if args.command == "tcp-test":  # the former name of `test`
            if args.list or args.name is None:
                return _cmd_test_list(config)
            return _cmd_test(config, args)
        if args.command == "scenario":
            if args.list or args.name is None:
                return _cmd_scenario_list(config)
            return _cmd_scenario(config, args.name)
        if args.command == "reset":
            return _cmd_reset(config)
        reply = _request(config, "status")  # status --json: the raw reply, printed as JSON below
    except NotImplementedError as exc:  # the stack lacks what this command needs
        print(f"error: your stack does not implement this yet: {exc}", file=sys.stderr)
        return 1
    except (ConfigError, TunnelClientError, OSError, ValueError, ImportError, PlanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(reply, indent=2, sort_keys=True))
    return 0 if reply.get("ok", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
