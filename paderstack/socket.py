"""The stdlib-named, stdlib-semantics socket API.

Application threads block here; every mutation of stack state is posted to
the stack thread via Runtime.run_in_stack, and waiting/waking uses
stackkit.sockets_base.StackSync (the stack's on_update callback wakes waiters
from the stack thread). Startup code calls install(runtime) once; application
code is then line-for-line identical to its stdlib version.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace, TracebackType
from typing import TYPE_CHECKING, Any

from paderstack.host import PaderStack
from paderstack.ipv4 import ip_to_bytes, ip_to_str
from paderstack.tcp_base import State, TcpConnectionBase, TcpListener
from stackkit.sockets_base import StackSync

if TYPE_CHECKING:
    from stackkit.runtime import Runtime

AF_INET = 2  # IPv4
SOCK_STREAM = 1  # TCP
SHUT_RD = 0  # shutdown: stop reading
SHUT_WR = 1  # shutdown: send the FIN
SHUT_RDWR = 2  # shutdown: both

error = OSError  # socket.error IS OSError since Python 3.3
timeout = TimeoutError  # socket.timeout IS TimeoutError since Python 3.10

_default_runtime: Runtime | None = None


def install(runtime: Runtime) -> None:
    """Bind the default runtime; called once by application startup code."""
    global _default_runtime
    _default_runtime = runtime


def bound_module(runtime: Runtime) -> SimpleNamespace:
    """A module-shaped namespace bound to a given runtime."""
    return SimpleNamespace(
        socket=lambda family=AF_INET, type=SOCK_STREAM: socket(family, type, _runtime=runtime),
        AF_INET=AF_INET,
        SOCK_STREAM=SOCK_STREAM,
        SHUT_RD=SHUT_RD,
        SHUT_WR=SHUT_WR,
        SHUT_RDWR=SHUT_RDWR,
        error=error,
        timeout=timeout,
    )


def _stack_of(runtime: Runtime) -> PaderStack:
    """The PaderStack a runtime hosts; OSError when it is not started."""
    stack = runtime.stack
    if not isinstance(stack, PaderStack):
        raise OSError("the runtime is not started, or does not host a paderstack stack")
    return stack


class socket:
    """A TCP socket on the student's stack, with the stdlib's methods and semantics."""

    def __init__(
        self,
        family: int = AF_INET,
        type: int = SOCK_STREAM,
        *,
        _runtime: Runtime | None = None,
        _conn: TcpConnectionBase | None = None,
    ) -> None:
        """A fresh socket on the installed runtime, or one wrapping an accepted connection."""

        # wrong family or type
        if family != AF_INET or type != SOCK_STREAM:
            raise OSError("this stack supports only AF_INET + SOCK_STREAM")

        # an explicit runtime wins over the installed default
        runtime = _runtime if _runtime is not None else _default_runtime
        if runtime is None:
            raise OSError("call paderstack.socket.install(runtime) before creating sockets")

        self._runtime = runtime  # the stack thread this socket posts to
        self._stack = _stack_of(runtime)  # the PaderStack it uses

        # the wait/wake primitive behind every blocking call
        self._sync = StackSync()

        # settimeout; None blocks forever
        self._timeout: float | None = None

        # the connection, once connected or accepted
        self._conn: TcpConnectionBase | None = None

        self._listener: TcpListener | None = None  # set by listen
        self._bound: tuple[str, int] | None = None  # (my IP, port) after bind
        self._closed = False  # close happened: every later call fails

        self._rd_shut = False  # shutdown(SHUT_RD): recv returns b"" from now on

        # accept builds the socket around a finished handshake
        if _conn is not None:
            self._adopt(_conn)

    # -- plumbing (provided) ---------------------------------------------------

    def _adopt(self, conn: TcpConnectionBase) -> None:
        """Take over a connection; its state changes wake this socket."""
        self._conn = conn
        conn.on_update = self._notify

    def _notify(self) -> None:
        """Called on the stack thread after a change: wake the blocked application thread."""
        with self._sync:
            self._sync.wake_all()

    def _in_stack(self, fn: Callable[[], Any]) -> Any:
        """Run fn on the stack thread and wait for its result."""

        # timeout of 30s is a guard against a deadlocked stack thread
        return self._runtime.run_in_stack(fn).result(timeout=30)

    def _check_open(self) -> None:
        """OSError once the socket is closed (the stdlib's EBADF)."""
        if self._closed:
            raise OSError("socket is closed (EBADF)")

    def _wait(self, predicate: Callable[[], bool], what: str) -> None:
        """Block per the settimeout value; raises socket.timeout on expiry."""

        # no timeout: wait as long as it takes
        if self._timeout is None:
            self._sync.wait_for(predicate)
            return
        if not self._sync.wait_for(predicate, timeout_s=self._timeout):
            raise timeout(f"timed out ({what})")

    def _raise_conn_error(self, conn: TcpConnectionBase) -> None:
        """Re-raise the connection's error (refused, reset, timed out) as a fresh exception."""
        if conn.error is not None:
            err = conn.error
            raise type(err)(*err.args)

    # -- connection establishment ----------------------------------------------

    def connect(self, address: tuple[str, int]) -> None:
        """Active connect; exceptions mapped to stdlib types (refused/timeout)."""
        self._check_open()
        if self._conn is not None:
            raise OSError("socket is already connected")
        host, port = address
        dst_ip = ip_to_bytes(host)
        conn = self._in_stack(lambda: self._stack.tcp.connect(dst_ip, port))
        self._adopt(conn)

        # the handshake ended, one way or the other
        def settled() -> bool:
            return conn.state is State.ESTABLISHED or conn.state is State.CLOSED

        # the handshake took too long: tear the connection down, re-raise
        try:
            self._wait(settled, "connect")
        except timeout:
            self._in_stack(conn.abort)
            raise
        self._raise_conn_error(conn)

        # CLOSED without a recorded error: a guard
        if conn.state is not State.ESTABLISHED:
            raise OSError("the connection could not be established")

    def bind(self, address: tuple[str, int]) -> None:
        """Bind to (host, port); host must be my own address, empty or 0.0.0.0."""
        self._check_open()
        host, port = address
        if host not in ("", "0.0.0.0", self._stack.config.network.student_ip):
            raise OSError(f"cannot bind to the non-local address {host!r}")
        if not 0 < port <= 65535:
            raise OSError(f"invalid port number: {port}")
        self._bound = (self._stack.config.network.student_ip, port)

    def listen(self, backlog: int = 5) -> None:
        """Start listening on the bound port (the backlog is accepted and ignored)."""
        self._check_open()
        if self._bound is None:
            raise OSError("bind must precede listen")
        port = self._bound[1]
        listener = self._in_stack(lambda: self._stack.tcp.listen(port))
        listener.on_update = self._notify
        self._listener = listener

    def accept(self) -> tuple[socket, tuple[str, int]]:
        """Block until a handshake completed; returns (socket, (peer IP, peer port))."""
        self._check_open()
        listener = self._listener
        if listener is None:
            raise OSError("listen must precede accept")
        self._wait(lambda: bool(listener.accept_queue), "accept")

        # the oldest completed connection
        def pop() -> TcpConnectionBase:
            return listener.accept_queue.pop(0)

        conn = self._in_stack(pop)
        child = socket(_runtime=self._runtime, _conn=conn)

        # do not miss state changes that happened before adoption
        child._notify()

        return child, (ip_to_str(conn.peer_ip), conn.peer_port)

    # -- data transfer ---------------------------------------------------------

    def send(self, data: bytes) -> int:
        """Returns once buffered (unbounded send buffer; never blocks)."""
        self._check_open()
        conn = self._require_conn()
        self._raise_conn_error(conn)
        payload = bytes(data)
        self._in_stack(lambda: conn.send(payload))
        return len(payload)

    def sendall(self, data: bytes) -> None:
        """Same as send: the whole data is buffered at once."""
        self.send(data)

    def recv(self, bufsize: int) -> bytes:
        """Blocking read; returns b"" after the peer FIN once the buffer drains."""
        self._check_open()

        # after SHUT_RD: the end of the stream, whatever arrives
        if self._rd_shut:
            return b""
        conn = self._require_conn()

        # something to return: data, the end of the stream, an error
        def ready() -> bool:
            return (
                len(conn.recv_buffer) > 0
                or conn.fin_received
                or conn.error is not None
                or conn.state is State.CLOSED
            )

        self._wait(ready, "recv")
        data = self._in_stack(lambda: conn.recv(bufsize))

        # data comes first; an error or the end of the stream only once it is drained
        if data:
            return bytes(data)
        self._raise_conn_error(conn)
        return b""

    def _require_conn(self) -> TcpConnectionBase:
        """The connection, or OSError when the socket is not connected."""
        if self._conn is None:
            raise OSError("socket is not connected")
        return self._conn

    # -- shutdown and close ----------------------------------------------------

    def shutdown(self, how: int) -> None:
        """SHUT_WR sends the FIN once the data is out; SHUT_RD makes recv return b""."""
        self._check_open()
        conn = self._require_conn()
        if how not in (SHUT_RD, SHUT_WR, SHUT_RDWR):
            raise OSError(f"invalid shutdown value: {how}")
        if how in (SHUT_WR, SHUT_RDWR):
            self._in_stack(conn.close)

        # the stack still takes data in; this socket stops handing it out
        if how in (SHUT_RD, SHUT_RDWR):
            self._rd_shut = True

    def close(self) -> None:
        """Stop listening and send the FIN if connected; a second close does nothing."""
        if self._closed:
            return
        self._closed = True
        conn, listener = self._conn, self._listener

        # stop listening; connections accepted earlier live on
        if listener is not None:
            self._in_stack(lambda: self._stack.tcp.unlisten(listener.port))

        # a connected socket: the orderly shutdown, the FIN follows the buffered data
        if conn is not None and conn.state is not State.CLOSED:
            self._in_stack(conn.close)

    # -- misc (provided) -----------------------------------------------------------

    def settimeout(self, value: float | None) -> None:
        """The timeout of the blocking calls in seconds; None (the default) blocks forever."""

        if value is not None and value < 0:
            raise ValueError("timeout cannot be negative")
        self._timeout = value

    def gettimeout(self) -> float | None:
        """The current timeout."""
        return self._timeout

    def getsockname(self) -> tuple[str, int]:
        """(my IP, local port): the connection's, else the bound one, else port 0."""
        if self._conn is not None:
            return (self._stack.config.network.student_ip, self._conn.local_port)
        if self._bound is not None:
            return self._bound
        return (self._stack.config.network.student_ip, 0)

    def getpeername(self) -> tuple[str, int]:
        """(peer IP, peer port) of the connection."""
        conn = self._require_conn()
        # refused, reset or timed out: there is no peer to name
        if conn.state is State.CLOSED and conn.error is not None:
            self._raise_conn_error(conn)
        return (ip_to_str(conn.peer_ip), conn.peer_port)

    def __enter__(self) -> socket:
        """with-statement support: the socket itself."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """with-statement support: close on exit."""
        self.close()
