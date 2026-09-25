//! The packet-oriented connection itself: raw sockets, the flow table, the capture loop, the
//! cleaner and the iptables rules that hold it all together.
//!
//! # How a dialled connection works
//!
//! 1. A **raw** `IPPROTO_TCP` socket is opened and connected to the remote IP, so the kernel
//!    hands us that peer's TCP traffic and a plain `send` reaches it.
//! 2. A **real** TCP connection is established: the kernel performs the handshake, so the path
//!    (NAT, firewalls, middleboxes) sees an ordinary TCP flow and keeps state for it.
//! 3. The capture loop starts. It watches the raw socket for segments addressed to our local
//!    port and keeps the flow's sequence and acknowledgement numbers in step with the peer.
//! 4. The real socket's **TTL is set to 1**, and a `filter/OUTPUT` rule drops everything with
//!    TTL 1 on that 5-tuple, so the kernel's own segments never leave the host. From here on the
//!    only traffic on the 5-tuple is what tcpraw writes through the raw socket.
//! 5. Whatever the peer's real stack sends on the connection is read and discarded.
//!
//! `WriteTo` then borrows the flow's state to craft a `PSH|ACK` segment around each datagram, and
//! the capture loop delivers the payload of every `PSH` segment it sees on a non-orphan flow.
//!
//! # How a listening connection works
//!
//! The same picture, once per peer and with the roles of the sockets swapped:
//!
//! 1. One **raw** socket is bound to each interface address (or to the one address the listen
//!    address names), and each runs its own capture loop, filtered on the listening port.
//! 2. A **real** TCP listener accepts the peers' connections. Every accepted connection gets
//!    TTL 1 and is recorded as its flow's `conn`, which is what makes that flow deliverable;
//!    a discard task drains it.
//! 3. One `filter/OUTPUT` rule per protocol — matching TTL 1 and the listening source port —
//!    keeps the kernel's own segments for *any* peer on the host.
//!
//! Go reference: `tcpraw@v1.2.32 tcp_linux.go`, `clear.go`.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::addr;
use crate::fingerprint::FingerPrint;
use crate::flow::{self, CLEANER_INTERVAL, RealConn, TcpFlow};
use crate::iface;
use crate::iptables::{self, CHAIN, IpTables, Protocol, TABLE};
use crate::raw::RawHandle;
use crate::tcp::{Segment, strip_ipv4_header};

/// The read buffer of the capture loop, Go's `buf := make([]byte, 2048)`.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).captureFlow()
const CAPTURE_BUF_SIZE: usize = 2048;

/// How many captured payloads may wait for the reader.
///
/// Go's `chMessage` is **unbuffered**: the capture loop blocks until `ReadFrom` takes the packet.
/// A tokio channel cannot have capacity 0, so this is the smallest bound that exists, which lets
/// exactly one packet sit in the channel where Go's sender would still be waiting. Nothing
/// observes the difference — the order is unchanged and no packet is dropped — and it keeps the
/// same backpressure on the capture loop. Raising it is a throughput question for Step 12, not a
/// correctness one.
const MESSAGE_BACKLOG: usize = 1;

/// Locks one of this module's plain mutexes, ignoring poisoning.
///
/// Each of them is held for a few field assignments and never across an `.await` (porting guide
/// §6), so a poisoned lock can only mean a panic inside such a block, which leaves no invariant
/// behind. This is the same helper `crates/kcp/src/io/mod.rs` uses, and the reason this crate
/// needs no lock dependency of its own.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A captured payload and the peer it came from.
// Go: tcpraw@v1.2.32 tcp_linux.go:message
#[derive(Debug)]
struct Message {
    bts: Vec<u8>,
    addr: SocketAddr,
}

/// The flow table and the fingerprint, under one lock.
///
/// Go keeps `tcpFingerPrint` on the connection rather than here, but only ever reads or rewrites
/// it inside a `lockflow` closure — i.e. under `flowsLock` — so this is the same object with the
/// lock it already had.
// Go: tcpraw@v1.2.32 tcp_linux.go:tcpConn.flowTable + .tcpFingerPrint
struct Flows {
    table: HashMap<SocketAddr, TcpFlow>,
    fingerprint: FingerPrint,
}

/// An iptables rule **this** connection appended, and the handle to remove it with.
///
/// A rule that already existed is not recorded, so `Close` never deletes an operator's rule.
// Go: tcpraw@v1.2.32 tcp_linux.go:tcpConn.{iptables,iprule,ip6tables,ip6rule}
struct InstalledRule {
    ipt: IpTables,
    rule: Vec<String>,
}

/// The shared state behind a [`TcpConn`], held by the connection's tasks as well.
// Go: tcpraw@v1.2.32 tcp_linux.go:tcpConn
pub struct TcpConnInner {
    /// Identifies this connection in the global list (Go's `elem` in `connList`).
    id: u64,
    /// Go's `die` channel: closed once, by `Close`.
    die: CancellationToken,
    /// Go's `dieOnce`.
    closed: AtomicBool,
    /// The real TCP connection of a **dialled** tcpraw connection; `None` on a listening one,
    /// which has [`listener`](Self::listener) instead and keeps its accepted connections in the
    /// flow table. Go branches on exactly this field throughout `tcp_linux.go`.
    tcpconn: Option<Arc<RealConn>>,
    /// The real TCP listener of a **listening** tcpraw connection; `None` on a dialled one.
    ///
    /// Behind a lock so that [`TcpConnInner::begin_close`] can let go of it where Go's `Close`
    /// closes it. The accept loop holds the other reference and drops it on `die`, so the
    /// listening socket is gone as soon as that loop has been scheduled once more.
    listener: Mutex<Option<Arc<tokio::net::TcpListener>>>,
    /// The raw sockets; a flow's `handle` is an index into this.
    ///
    /// Behind a lock so that [`TcpConnInner::begin_close`] can let go of them where Go's `Close`
    /// closes them; the indices stay valid because the vector is only ever cleared as a whole.
    handles: Mutex<Vec<Arc<RawHandle>>>,
    /// The capture loops' end of the delivery channel.
    tx: mpsc::Sender<Message>,
    /// The reader's end. Only one task reads at a time, which is what the async mutex enforces.
    rx: tokio::sync::Mutex<mpsc::Receiver<Message>>,
    flows: Mutex<Flows>,
    /// Filled in after the connection is up, hence the lock — by the blocking task that installs
    /// them ([`TcpConnInner::store_rules`]), which may well outlive the `dial` that asked for it.
    rules: Mutex<Vec<InstalledRule>>,
    local_addr: SocketAddr,
}

/// A packet-oriented connection carried inside a real TCP connection.
///
/// Dropping it closes the connection and removes the iptables rules, which is what Go's
/// `runtime.SetFinalizer` in `wrapConn` does. It is deliberately not `Clone`: share it through an
/// [`Arc`] so there is exactly one close.
// Go: tcpraw@v1.2.32 tcp_linux.go:TCPConn, wrapConn()
pub struct TcpConn {
    inner: Arc<TcpConnInner>,
}

impl TcpConn {
    /// Waits for the next datagram, copying as much of it as fits into `p`.
    ///
    /// A closed connection reports `EOF`, as Go's `ReadFrom` does. There are no deadlines: Go's
    /// `SetReadDeadline` exists on a `net.PacketConn` but kcp-go never calls it on the transport,
    /// and this port's [`PacketConn`](kcptun_kcp::PacketConn) has no such method, so a receive is
    /// ended by cancelling the future or by closing the connection.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).ReadFrom()
    pub async fn recv_from(&self, p: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(p).await
    }

    /// Wraps `p` in a crafted TCP segment for `target` and sends it.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).WriteTo()
    pub async fn send_to(&self, p: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(p, target).await
    }

    /// The local address of the real TCP connection: the source of every crafted segment.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).LocalAddr()
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Sets the DSCP code point (IPv4 TOS, IPv6 traffic class) of every raw socket this
    /// connection sends through, stopping at the first failure as Go does.
    ///
    /// A connection with no handles — one that has been closed — succeeds without doing
    /// anything, which is Go's empty `for k := range conn.handles`.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetDSCP()
    pub fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        for handle in self.inner.handle_snapshot() {
            handle.set_dscp(dscp)?;
        }
        Ok(())
    }

    /// Sets the receive buffer (`SO_RCVBUF`) of every raw socket of this connection.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetReadBuffer()
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        for handle in self.inner.handle_snapshot() {
            handle.set_read_buffer(bytes)?;
        }
        Ok(())
    }

    /// Sets the send buffer (`SO_SNDBUF`) of every raw socket of this connection.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetWriteBuffer()
    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        for handle in self.inner.handle_snapshot() {
            handle.set_write_buffer(bytes)?;
        }
        Ok(())
    }

    /// Closes the connection: restores the TTL, shuts the real socket down, removes the iptables
    /// rules this connection added and stops every task. Calling it twice is harmless.
    ///
    /// It **blocks** while `iptables`/`ip6tables` run, as Go's `Close` does, so that the rules
    /// are gone by the time it returns — which is what makes it usable from `Drop` and from the
    /// process-exit path. A caller that is already on the tokio runtime should use
    /// [`close_async`](Self::close_async) instead, which runs those subprocesses on a blocking
    /// thread. Go returns the error of closing the real socket here; there is none to return,
    /// since the socket is shut down rather than closed (see [`RealConn::close`]).
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).Close()
    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }

    /// [`close`](Self::close) for a caller on the tokio runtime: everything but the `iptables`
    /// invocations happens at once, and those run on a blocking thread, so no worker is held for
    /// the lifetime of a subprocess (which, with go-iptables' bare `--wait`, can be until another
    /// process releases the xtables lock).
    ///
    /// It still returns only once the rules are gone, and the later `Drop` finds nothing to do.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).Close()
    pub async fn close_async(&self) {
        if !self.inner.begin_close() {
            return;
        }
        let inner = self.inner.clone();
        // A `JoinError` can only be a panic in `iptables.delete`, which is already ignored below.
        let _ = tokio::task::spawn_blocking(move || inner.delete_rules()).await;
    }
}

impl Drop for TcpConn {
    // Go: tcpraw@v1.2.32 tcp_linux.go:wrapConn() (`runtime.SetFinalizer(wrapper, …Close())`)
    fn drop(&mut self) {
        let _ = self.inner.close();
    }
}

impl std::fmt::Debug for TcpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConn")
            .field("local_addr", &self.inner.local_addr)
            .field("handles", &lock(&self.inner.handles).len())
            .finish()
    }
}

impl TcpConnInner {
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).ReadFrom()
    async fn recv_from(&self, p: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        tokio::select! {
            () = self.die.cancelled() => Err(eof()),
            msg = rx.recv() => match msg {
                Some(msg) => {
                    // Go: `n = copy(p, packet.bts)` — a datagram longer than `p` is truncated.
                    let n = p.len().min(msg.bts.len());
                    p[..n].copy_from_slice(&msg.bts[..n]);
                    Ok((n, msg.addr))
                }
                None => Err(eof()),
            },
        }
    }

    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).WriteTo()
    async fn send_to(&self, p: &[u8], target: SocketAddr) -> io::Result<usize> {
        if self.die.is_cancelled() {
            return Err(eof());
        }
        let key = addr::canonical(target);
        let lport = self.local_addr.port();

        // Everything up to the send happens under the flow lock, as in Go; only the send itself
        // is outside it, because a task must not hold a mutex across an await (porting guide §6).
        // Two concurrent writes to the *same* peer can therefore leave in the other order — which
        // nothing observes, since the receiver takes each segment's payload as it arrives and
        // never reassembles by sequence number.
        let built = {
            let mut guard = lock(&self.flows);
            let Flows { table, fingerprint } = &mut *guard;
            let flow = table
                .entry(key)
                .or_insert_with(|| TcpFlow::new(Instant::now()));
            let handle = flow
                .handle
                .and_then(|index| lock(&self.handles).get(index).cloned());
            match handle {
                // Go: "if the flow doesn't have handle, assume this packet has lost, without
                // notification".
                None => None,
                Some(handle) => {
                    let src_ip = handle.local_ip();
                    let mut buf = std::mem::take(&mut flow.buf);
                    let ok = flow.build_segment(fingerprint, lport, target, src_ip, p, &mut buf);
                    Some((handle, buf, ok))
                }
            }
        };

        let Some((handle, buf, ok)) = built else {
            return Ok(p.len());
        };
        let result = if ok {
            Some(handle.send_to(&buf, target.ip()).await)
        } else {
            None
        };
        self.return_buf(key, buf);
        match result {
            // Go sets `n = len(p)` after the write and returns it even when the write failed;
            // an `io::Result` has to choose, and the caller only ever looks at the error.
            Some(Err(err)) => Err(err),
            _ => Ok(p.len()),
        }
    }

    /// The raw sockets, cloned out from under the lock.
    ///
    /// The `setsockopt` calls of the three setters above run outside the critical section
    /// (DECISIONS D02), and a closed connection simply has none left.
    fn handle_snapshot(&self) -> Vec<Arc<RawHandle>> {
        lock(&self.handles).clone()
    }

    /// Gives the serialisation buffer back to its flow, so the next segment reuses the
    /// allocation (Go keeps one `gopacket.SerializeBuffer` per flow).
    fn return_buf(&self, key: SocketAddr, buf: Vec<u8>) {
        let mut guard = lock(&self.flows);
        if let Some(flow) = guard.table.get_mut(&key)
            && flow.buf.capacity() < buf.capacity()
        {
            flow.buf = buf;
        }
    }

    /// Everything `Close` does except running `iptables`: stops the tasks, shuts the real socket
    /// down, releases the raw sockets and unregisters the connection.
    ///
    /// Returns `false` when another caller got there first, which is Go's `dieOnce.Do`. `closed`
    /// is set **before** the `rules` lock is ever taken, which is what lets [`store_rules`] and
    /// [`delete_rules`] hand the dial path's rules to exactly one of them.
    ///
    /// [`store_rules`]: TcpConnInner::store_rules
    /// [`delete_rules`]: TcpConnInner::delete_rules
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).Close()
    fn begin_close(&self) -> bool {
        if self.closed.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.die.cancel();

        if let Some(conn) = &self.tcpconn {
            // Go: `setTTL(conn.tcpconn, 64); err = conn.tcpconn.Close()`.
            conn.close();
        } else if let Some(listener) = lock(&self.listener).take() {
            // Go: `err = conn.listener.Close()`, then every accepted connection in the flow
            // table is given TTL 64, closed and removed. Dropping this reference leaves the
            // accept loop holding the last one, and it stops on `die` — the same few
            // microseconds' delay as the raw handles below, and just as unobservable.
            drop(listener);

            // Go closes the accepted connections inside `flowsLock`; doing it just outside keeps
            // the syscalls out of the critical section (DECISIONS D02), as the cleaner does.
            let closing: Vec<Arc<RealConn>> = {
                let mut guard = lock(&self.flows);
                guard
                    .table
                    .drain()
                    .filter_map(|(_, flow)| flow.conn)
                    .collect()
            };
            for real in closing {
                real.close();
            }
        }

        // Go: `for k := range conn.handles { conn.handles[k].Close() }`. Letting go of the
        // connection's own references leaves the capture loops holding the last one each, and
        // those stop on `die`, so every descriptor is closed as soon as its loop has been
        // scheduled once more — a few microseconds later than Go's explicit `Close`, and never
        // observable on the wire.
        lock(&self.handles).clear();

        remove_from_conn_list(self.id);
        true
    }

    /// Removes the iptables rules this connection appended.
    ///
    /// Blocking: it runs `iptables`/`ip6tables` as subprocesses.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).Close() (the two `Delete` calls)
    fn delete_rules(&self) {
        let installed: Vec<InstalledRule> = lock(&self.rules).drain(..).collect();
        for rule in installed {
            let _ = rule.ipt.delete(TABLE, CHAIN, &rule.rule);
        }
    }

    /// Records the rules the dial path installed — or, when the connection was closed while they
    /// were being installed, removes them again on the spot.
    ///
    /// The window is real: `dial` hands the installation to a blocking task, and that task runs
    /// to the end even if the `dial` future is dropped or the connection is closed meanwhile.
    /// [`begin_close`](Self::begin_close) sets `closed` before it takes any lock and
    /// [`delete_rules`](Self::delete_rules) drains under the `rules` lock, so one of the two
    /// always sees the rules: either they are in the vector when `delete_rules` drains it, or
    /// `closed` is already true here.
    fn store_rules(&self, installed: Vec<InstalledRule>) {
        {
            let mut guard = lock(&self.rules);
            if !self.closed.load(Ordering::SeqCst) {
                *guard = installed;
                return;
            }
        }
        // Closed already: these rules are this connection's, and nothing else will delete them.
        for rule in installed {
            let _ = rule.ipt.delete(TABLE, CHAIN, &rule.rule);
        }
    }

    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).Close()
    fn close(&self) -> io::Result<()> {
        if self.begin_close() {
            self.delete_rules();
        }
        // Go's `dieOnce.Do`: the second caller runs nothing and gets the zero error value.
        Ok(())
    }
}

/// Go's `io.EOF`, the error a closed connection reports from `ReadFrom` and `WriteTo`.
fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

/// Connects to `address`, hiding a packet transport inside the resulting TCP connection.
///
/// Needs `CAP_NET_RAW` for the raw socket. The iptables rules are best effort, exactly as in Go:
/// if `iptables` is missing or refuses the rule, the connection still works, because the TTL of 1
/// already keeps the kernel's segments from leaving the host — but the first hop will answer ICMP
/// Time Exceeded.
///
/// # Ordering
///
/// The steps below are Go's, in Go's order, with one exception: the connection joins the global
/// list before the iptables rules are installed rather than after. Go's `Dial` cannot be
/// cancelled, a Rust future can be dropped at any `.await`, and from the moment the tasks are
/// spawned there is state that only `close` undoes — so the connection is registered and guarded
/// first (see [`CloseOnCancel`]). Nothing observes the difference: the list is only read by
/// [`iptables_reset`], for which a half-built connection is a connection to close like any other.
///
/// The flow is recorded and the capture loop is running **before** the TTL is lowered, exactly as
/// in Go, so no segment of the live connection is missed.
// Go: tcpraw@v1.2.32 tcp_linux.go:Dial()
pub async fn dial(network: &str, address: &str) -> io::Result<TcpConn> {
    // Go resolves on the calling goroutine, where a blocking lookup costs a thread the runtime
    // can replace; a blocked tokio worker is not replaced, so the lookup goes to a blocking task.
    let network = network.to_string();
    let (resolve_network, address) = (network.clone(), address.to_string());
    let resolved =
        tokio::task::spawn_blocking(move || addr::resolve_tcp_addr(&resolve_network, &address))
            .await;
    let raddr = match resolved {
        Ok(result) => result?,
        // A `JoinError` here can only be a panic inside the resolver.
        Err(err) => return Err(io::Error::other(err)),
    };
    // Go's `net.TCPAddr` holds the 4-byte form of an IPv4-mapped address from here on; unmapping
    // it once keeps the raw socket, the flow key and the rule's `-d` operand in agreement.
    let raddr = addr::canonical(raddr);

    // The raw socket first, so a missing CAP_NET_RAW is reported before anything is dialled.
    // (Go leaks this handle if the TCP connect below fails; here it is simply dropped.)
    let handle = RawHandle::dial(raddr.ip())?;

    // The real connection, whose 5-tuple every crafted segment pretends to belong to.
    //
    // Go: `net.DialTCP(network, nil, raddr)`, whose failure is an
    // `&net.OpError{Op: "dial", Net: network, Addr: raddr, Err: os.NewSyscallError("connect", …)}`
    // — `dial tcp 203.0.113.1:29900: connect: connection refused`. `raddr` is already unmapped,
    // so its `Display` is Go's `TCPAddr.String()` (`net.JoinHostPort(ip.String(), port)`).
    let tcpconn = tokio::net::TcpStream::connect(raddr).await.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "dial {network} {raddr}: connect: {text}",
                text = addr::errno_text(&err)
            ),
        )
    })?;
    let local_addr = tcpconn.local_addr()?;
    let peer_addr = addr::canonical(tcpconn.peer_addr()?);

    // Go: `net.SplitHostPort(tcpconn.LocalAddr().String())`, the `-s`/`--sport` operands. Go
    // splits the string because that is where it has the address; `net.IP.String()` has already
    // printed an IPv4-mapped address as a dotted quad by then. Rust's `Display` prints
    // `[::ffff:10.0.0.1]:54321`, which `iptables` rejects, so the two operands are taken from the
    // `SocketAddr` itself — `ip_string` being exactly `net.IP.String()`.
    let laddr = addr::ip_string(local_addr.ip());
    let lport = local_addr.port().to_string();

    let real = Arc::new(RealConn::new(tcpconn));
    let (tx, rx) = mpsc::channel(MESSAGE_BACKLOG);

    // Go: `conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })`.
    let mut table = HashMap::new();
    let mut flow = TcpFlow::new(Instant::now());
    flow.conn = Some(real.clone());
    table.insert(peer_addr, flow);

    let inner = Arc::new(TcpConnInner {
        id: next_conn_id(),
        die: CancellationToken::new(),
        closed: AtomicBool::new(false),
        tcpconn: Some(real.clone()),
        listener: Mutex::new(None),
        handles: Mutex::new(vec![Arc::new(handle)]),
        tx,
        rx: tokio::sync::Mutex::new(rx),
        flows: Mutex::new(Flows {
            table,
            // Go: `fingerPrintLinux.Clone()` — one per connection, shared by its flows.
            fingerprint: FingerPrint::linux(),
        }),
        rules: Mutex::new(Vec::new()),
        local_addr,
    });

    // Go: `go conn.captureFlow(handle, tcpconn.LocalAddr().(*net.TCPAddr).Port)`, `go conn.cleaner()`.
    tokio::spawn(capture_flow(inner.clone(), 0, local_addr.port()));
    tokio::spawn(cleaner(inner.clone()));

    // Go: `conn.elem = connList.PushBack(conn)`, which Go does at the very end — see "Ordering".
    push_conn(inner.clone());
    let guard = CloseOnCancel(Some(inner.clone()));

    // From here on the kernel's own segments on this 5-tuple must not escape the host.
    //
    // Go calls `conn.Close()` on failure, which panics in `connList.Remove(nil)` because the
    // connection has not been registered yet; here it is registered, and the guard closes it.
    real.set_ttl(1)?;

    // Go installs each rule only when it is not there already, and remembers only the ones it
    // appended itself. Every failure is ignored: no rule, but a working connection.
    //
    // The blocking task records what it installed itself, rather than handing it back to this
    // future: a `spawn_blocking` task cannot be cancelled, so if `dial` is dropped at this await
    // the rules are still appended — and they have to be remembered (or removed again) whatever
    // becomes of this future. `store_rules` does the one or the other.
    let rip = addr::ip_string(raddr.ip());
    let rport = raddr.port();
    let rules_inner = inner.clone();
    // A `JoinError` can only be a panic in `setup_dial_rules`; there is then nothing to record.
    let _ = tokio::task::spawn_blocking(move || {
        rules_inner.store_rules(setup_dial_rules(&laddr, &lport, &rip, rport));
    })
    .await;

    // Go: `go io.Copy(ioutil.Discard, tcpconn)` — the peer's real TCP stack keeps talking.
    tokio::spawn(discard(real, inner.die.clone()));

    // The connection is complete: closing it is `TcpConn`'s job from here.
    guard.disarm();
    Ok(TcpConn { inner })
}

/// Closes a half-built connection when the `dial` future is dropped before it returns one.
///
/// Go's `Dial` runs to completion once it is called; a Rust future can be dropped at any `.await`,
/// and a `dial` inside a `tokio::select!` or a `tokio::time::timeout` would otherwise leave the
/// tasks, the raw socket, the real TCP connection and — worst — the `filter/OUTPUT` rules behind,
/// with no `TcpConn` whose `Drop` could clean them up.
struct CloseOnCancel(Option<Arc<TcpConnInner>>);

impl CloseOnCancel {
    /// Hands the connection over to the caller of `dial`.
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CloseOnCancel {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            let _ = inner.close();
        }
    }
}

/// Installs the IPv4 and IPv6 `filter/OUTPUT` DROP rules for a dialled connection and returns the
/// ones this process appended.
///
/// Blocking: it runs `iptables`/`ip6tables` as subprocesses, which is why `dial` calls it from a
/// blocking task.
// Go: tcpraw@v1.2.32 tcp_linux.go:Dial() (the two `iptables.NewWithProtocol` blocks)
fn setup_dial_rules(laddr: &str, lport: &str, rip: &str, rport: u16) -> Vec<InstalledRule> {
    let mut installed = Vec::new();
    for proto in [Protocol::IPv4, Protocol::IPv6] {
        // Go: `if ipt, err := iptables.NewWithProtocol(…); err == nil` — no binary, no rule.
        let Ok(ipt) = IpTables::new_with_protocol(proto) else {
            continue;
        };
        let rule = iptables::dial_rule(proto, laddr, lport, rip, rport);
        // Go: `if exists, err := ipt.Exists(…); err == nil { if !exists { … } }`.
        let Ok(false) = ipt.exists(TABLE, CHAIN, &rule) else {
            continue;
        };
        if ipt.append(TABLE, CHAIN, &rule).is_ok() {
            installed.push(InstalledRule { ipt, rule });
        }
    }
    installed
}

/// Listens on `address`, serving every peer that connects as a packet transport.
///
/// Needs `CAP_NET_RAW` for the raw sockets. The iptables rules are best effort, exactly as in Go
/// (the TODO in Go's source says the same thing): without them the connection still works,
/// because the TTL of 1 already keeps the kernel's segments from leaving the host, but the first
/// hop will answer ICMP Time Exceeded.
///
/// One raw socket is opened per **interface address** when `address` names no address or the
/// wildcard, and one for the address it names otherwise; each gets its own capture loop, filtered
/// on the listening port. The real `TcpListener` accepts the peers' kernel-level connections,
/// which hold the 5-tuples the crafted segments belong to.
///
/// # Ordering
///
/// Go's order, with two differences, neither of them observable:
///
/// - the connection is built (and its capture loops started) **after** the TCP listener is bound,
///   where Go starts the capture goroutines first and closes the handles again if the bind fails.
///   Nothing can arrive for the port in that window but traffic addressed to a port nobody is
///   listening on, and the kernel queues it on the raw socket until the loop starts anyway;
/// - the connection joins the global list before the iptables rules are installed rather than
///   after, so that a `listen` future dropped at an `.await` still cleans up — see `dial`'s
///   "Ordering" and [`CloseOnCancel`].
// Go: tcpraw@v1.2.32 tcp_linux.go:Listen()
pub async fn listen(network: &str, address: &str) -> io::Result<TcpConn> {
    // As in `dial`: the (possibly blocking) resolver runs off the runtime's worker threads.
    let network = network.to_string();
    // The caller's spelling is kept: `listen_op_error` needs it to tell `:29900` (Go's nil
    // `TCPAddr.IP`) from an address that really named the wildcard.
    let address = address.to_string();
    let (resolve_network, resolve_address) = (network.clone(), address.clone());
    let resolved = tokio::task::spawn_blocking(move || {
        addr::resolve_tcp_addr(&resolve_network, &resolve_address)
    })
    .await;
    let laddr = match resolved {
        Ok(result) => result?,
        // A `JoinError` here can only be a panic inside the resolver.
        Err(err) => return Err(io::Error::other(err)),
    };

    // Go: `ifaces, err := net.Interfaces()` — asked for before it is known whether the address
    // even needs them, and a failure there fails the listen.
    let ifaces = iface::interface_addrs()?;

    // Go: "if address is not specified, capture on all ifaces". Go's `laddr.IP` is nil for an
    // address without a host, which `resolve_tcp_addr` reports as `0.0.0.0` — unspecified either
    // way.
    let handles = if laddr.ip().is_unspecified() {
        let mut handles = Vec::new();
        let mut lasterr = None;
        for ip in ifaces {
            match RawHandle::listen(ip) {
                Ok(handle) => handles.push(Arc::new(handle)),
                Err(err) => lasterr = Some(err),
            }
        }
        if handles.is_empty() {
            // Go returns `nil, lasterr` — and `lasterr` is nil when the host listed no address at
            // all, which hands the caller a nil connection with a nil error to dereference. An
            // `io::Result` has to name the failure, so this one does.
            return Err(lasterr.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no interface address to capture on",
                )
            }));
        }
        handles
    } else {
        vec![Arc::new(RawHandle::listen(laddr.ip())?)]
    };

    // Go: `l, err := net.ListenTCP(network, laddr)`, which closes the handles on failure — here
    // they are simply dropped with `handles`. Its `*net.OpError` is the error a privileged
    // `--tcp` server actually sees (`listen tcp :29900: bind: address already in use`), so it is
    // spelled Go's way — see `addr::listen_op_error`.
    let listener = addr::listen_tcp(&network, laddr)
        .map_err(|err| addr::listen_op_error(&network, &address, laddr, err))?;
    let listener = Arc::new(tokio::net::TcpListener::from_std(listener)?);
    // Go's `LocalAddr()` is `listener.Addr()`, which is also the source port of every crafted
    // segment. The capture filter and the iptables rules use the *resolved* port instead, just
    // as Go does; the two differ only for a `:0` listen.
    let local_addr = listener.local_addr()?;

    let (tx, rx) = mpsc::channel(MESSAGE_BACKLOG);
    let handle_count = handles.len();
    let inner = Arc::new(TcpConnInner {
        id: next_conn_id(),
        die: CancellationToken::new(),
        closed: AtomicBool::new(false),
        tcpconn: None,
        listener: Mutex::new(Some(listener.clone())),
        handles: Mutex::new(handles),
        tx,
        rx: tokio::sync::Mutex::new(rx),
        flows: Mutex::new(Flows {
            table: HashMap::new(),
            // Go: `fingerPrintLinux.Clone()` — one per connection, shared by its flows.
            fingerprint: FingerPrint::linux(),
        }),
        rules: Mutex::new(Vec::new()),
        local_addr,
    });

    // Go: `go conn.captureFlow(handle, laddr.Port)` for each handle, then `go conn.cleaner()`.
    for index in 0..handle_count {
        tokio::spawn(capture_flow(inner.clone(), index, laddr.port()));
    }
    tokio::spawn(cleaner(inner.clone()));

    // Go: `conn.elem = connList.PushBack(conn)`, which Go does at the very end — see "Ordering".
    push_conn(inner.clone());
    let guard = CloseOnCancel(Some(inner.clone()));

    // Go installs each rule only when it is not there already, and remembers only the ones it
    // appended itself. Every failure is ignored: no rule, but a working connection. As in `dial`,
    // the blocking task records what it installed rather than handing it back, because it runs to
    // the end even if this future is dropped at the await below.
    let rules_inner = inner.clone();
    let lport = laddr.port();
    // A `JoinError` can only be a panic in `setup_listen_rules`; there is then nothing to record.
    let _ = tokio::task::spawn_blocking(move || {
        rules_inner.store_rules(setup_listen_rules(lport));
    })
    .await;

    // Go: the accept goroutine ("discard everything in original connection").
    tokio::spawn(accept_loop(inner.clone(), listener));

    // The connection is complete: closing it is `TcpConn`'s job from here.
    guard.disarm();
    Ok(TcpConn { inner })
}

/// Installs the IPv4 and IPv6 `filter/OUTPUT` DROP rules of a listening connection and returns
/// the ones this process appended.
///
/// Blocking: it runs `iptables`/`ip6tables` as subprocesses, which is why `listen` calls it from
/// a blocking task.
// Go: tcpraw@v1.2.32 tcp_linux.go:Listen() (the two `iptables.NewWithProtocol` blocks)
fn setup_listen_rules(lport: u16) -> Vec<InstalledRule> {
    let mut installed = Vec::new();
    for proto in [Protocol::IPv4, Protocol::IPv6] {
        // Go: `if ipt, err := iptables.NewWithProtocol(…); err == nil` — no binary, no rule.
        let Ok(ipt) = IpTables::new_with_protocol(proto) else {
            continue;
        };
        let rule = iptables::listen_rule(proto, lport);
        // Go: `if exists, err := ipt.Exists(…); err == nil { if !exists { … } }`.
        let Ok(false) = ipt.exists(TABLE, CHAIN, &rule) else {
            continue;
        };
        if ipt.append(TABLE, CHAIN, &rule).is_ok() {
            installed.push(InstalledRule { ipt, rule });
        }
    }
    installed
}

/// Accepts the peers' real TCP connections, pins each one's TTL to 1, records it as its flow's
/// connection — which is what lifts the flow out of orphan state and makes its packets
/// deliverable — and drains it.
// Go: tcpraw@v1.2.32 tcp_linux.go:Listen() (the accept goroutine)
async fn accept_loop(conn: Arc<TcpConnInner>, listener: Arc<tokio::net::TcpListener>) {
    loop {
        // The peer address comes from `accept(2)` itself, as Go's `tcpconn.RemoteAddr()` does:
        // it is the address the kernel handed back with the socket, so it is always available
        // and costs no extra syscall — unlike `getpeername(2)`, which answers `ENOTCONN` once
        // the peer has already reset the connection.
        let (stream, peer) = tokio::select! {
            () = conn.die.cancelled() => return,
            result = listener.accept() => match result {
                Ok(accepted) => accepted,
                // Go: `if err != nil { return }` — the listener is closed, so is this loop.
                Err(_) => return,
            },
        };

        let real = Arc::new(RealConn::new(stream));
        // Go: "if we cannot set TTL = 1, the only thing reasonable is panic". A panic in a spawned
        // task would only end the task here, and letting the peer's kernel talk on a connection
        // whose segments leave the host is exactly what tcpraw exists to prevent — so the process
        // goes down, which is what Go's panic does under DECISIONS D24 (`panic = "abort"`).
        //
        // `abort(2)` runs neither the panic hook nor the exit hooks, so the rules are removed
        // here, by hand, before the process goes — the one thing this path must not leave behind
        // (Go leaves them: its `panic` reaches no `postProcess` either). `iptables_reset` closes
        // every connection of the process, this one included, and holds no lock this loop holds.
        if let Err(err) = real.set_ttl(1) {
            // Go's panic carries the `syscall.Errno` itself, so the errno is spelled from Go's
            // own table here too (D30) rather than by Rust's `Display`.
            eprintln!(
                "tcpraw: cannot set TTL on an accepted connection: {}",
                addr::errno_text(&err)
            );
            iptables_reset();
            std::process::abort();
        }

        // Go: `conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })`.
        {
            let now = Instant::now();
            let mut guard = lock(&conn.flows);
            guard
                .table
                .entry(addr::canonical(peer))
                .or_insert_with(|| TcpFlow::new(now))
                .conn = Some(real.clone());
        }

        // Go: `go io.Copy(ioutil.Discard, tcpconn)`.
        tokio::spawn(discard(real, conn.die.clone()));
    }
}

/// Watches one raw socket, keeps the flow table in step with the peer's real TCP header and
/// delivers the payload of every `PSH` segment on a non-orphan flow.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).captureFlow()
async fn capture_flow(conn: Arc<TcpConnInner>, index: usize, port: u16) {
    let Some(handle) = lock(&conn.handles).get(index).cloned() else {
        return;
    };
    let mut buf = vec![0u8; CAPTURE_BUF_SIZE];
    loop {
        let (n, from) = tokio::select! {
            () = conn.die.cancelled() => return,
            result = handle.recv_from(&mut buf) => match result {
                Ok(read) => read,
                // Go: `if err != nil { return }` — the handle is gone, so is this loop.
                Err(_) => return,
            },
        };

        // An IPv4 raw socket delivers the IP header too. `strip_ipv4_header` must see the whole
        // buffer, not `buf[..n]`: Go's `ReadFromIP` compares the header length against the
        // buffer, not against the number of bytes read.
        let n = if handle.is_v4() {
            strip_ipv4_header(n, &mut buf)
        } else {
            n
        };

        // Go hands `captureFlow` an all-zero `layers.TCP` for a buffer this short, whose
        // destination port 0 never matches the filter below; skipping it is the same thing,
        // because a bound socket's port is never 0.
        let Ok(segment) = Segment::decode(&buf[..n]) else {
            continue;
        };

        // Go: "port filtering".
        if segment.header.dst_port != port {
            continue;
        }

        // Go: "address building" — the source IP of the packet with the segment's source port.
        let src = addr::canonical(SocketAddr::new(from, segment.header.src_port));

        let orphan = {
            let now = Instant::now();
            let mut guard = lock(&conn.flows);
            guard
                .table
                .entry(src)
                .or_insert_with(|| TcpFlow::new(now))
                .capture_update(&segment, index, now)
        };

        // Go: "push data if it's not orphan".
        if !orphan && segment.header.flags.psh() {
            let message = Message {
                bts: segment.payload.to_vec(),
                addr: src,
            };
            tokio::select! {
                () = conn.die.cancelled() => return,
                result = conn.tx.send(message) => if result.is_err() { return },
            }
        }
    }
}

/// Expires idle flows every five seconds.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).cleaner()
async fn cleaner(conn: Arc<TcpConnInner>) {
    let mut ticker = tokio::time::interval(CLEANER_INTERVAL);
    // `interval` fires at once; Go's `time.NewTicker` waits out the first period.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        tokio::select! {
            () = conn.die.cancelled() => return,
            _ = ticker.tick() => {
                let now = Instant::now();
                // Go closes the expired connections inside the lock; doing it just outside keeps
                // the syscalls out of the critical section (DECISIONS D02) and is otherwise the
                // same sequence: TTL 64, then close.
                let closing = {
                    let mut guard = lock(&conn.flows);
                    flow::sweep(&mut guard.table, now)
                };
                for real in closing {
                    real.close();
                }
            }
        }
    }
}

/// Reads and throws away everything the peer's real TCP stack sends, so the receive buffer never
/// fills up and stalls the connection.
// Go: tcpraw@v1.2.32 tcp_linux.go:Dial() (`go io.Copy(ioutil.Discard, tcpconn)`)
async fn discard(real: Arc<RealConn>, die: CancellationToken) {
    let mut buf = [0u8; CAPTURE_BUF_SIZE];
    loop {
        tokio::select! {
            () = die.cancelled() => return,
            readable = real.stream().readable() => {
                if readable.is_err() {
                    return;
                }
                match real.stream().try_read(&mut buf) {
                    // End of stream: `io.Copy` returns here too.
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return,
                }
            }
        }
    }
}

/// Every live connection, so that [`iptables_reset`] can clean up on a signal.
// Go: tcpraw@v1.2.32 tcp_linux.go:connList, connListMu
static CONN_LIST: Mutex<Vec<(u64, Arc<TcpConnInner>)>> = Mutex::new(Vec::new());
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(0);

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

fn push_conn(conn: Arc<TcpConnInner>) {
    lock(&CONN_LIST).push((conn.id, conn));
}

fn remove_from_conn_list(id: u64) {
    lock(&CONN_LIST).retain(|(other, _)| *other != id);
}

/// Closes every tcpraw connection of this process, which is what removes their iptables rules.
///
/// kcptun calls this from its signal handler and on the normal exit paths; a `SIGKILL` cannot be
/// caught, and then the rules survive — exactly as with Go, whose documentation points at a
/// manual cleanup script for that case.
///
/// Go closes the connections concurrently, one goroutine each, and waits for all of them. This
/// does it one after another: every close is a couple of `iptables` invocations, so the wall
/// time is the same order and the sequence of rules removed is identical.
///
/// **Blocking**: it runs `iptables`/`ip6tables` as subprocesses, each waiting for the xtables
/// lock without a timeout. This is the call the signal path uses — it has no [`TcpConn`] to
/// reach [`TcpConn::close_async`] through — and it is registered as an exit hook by
/// `kcptun_std::signal::register_iptables_reset`, which deliberately lets it block the
/// signal-handling task: Go's `postProcess()` blocks the signal goroutine in exactly the same
/// way, and the 5 s fallback `exit(0)` task is already armed before the hooks run. A caller
/// elsewhere on the tokio runtime, where blocking a worker is not wanted, should wrap it in
/// `tokio::task::spawn_blocking`.
// Go: tcpraw@v1.2.32 clear.go:IPTablesReset()
pub fn iptables_reset() {
    let conns: Vec<Arc<TcpConnInner>> = lock(&CONN_LIST)
        .iter()
        .map(|(_, conn)| conn.clone())
        .collect();
    for conn in conns {
        let _ = conn.close();
    }
}

/// Connections built by hand, for the tests of this crate that need no privilege.
///
/// It lives here rather than in `mod tests` because [`crate::packet_conn`]'s tests need the same
/// connection, and a `#[cfg(test)]` item is not reachable from a sibling module's test module.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A connection with no sockets and no tasks: enough for the flow table, the close sequence,
    /// the option setters and the rule bookkeeping, none of which needs a raw socket. It is
    /// deliberately **not** in `CONN_LIST`, so tests using it cannot disturb each other.
    pub(crate) fn detached_conn() -> TcpConn {
        let (tx, rx) = mpsc::channel(MESSAGE_BACKLOG);
        TcpConn {
            inner: Arc::new(TcpConnInner {
                id: next_conn_id(),
                die: CancellationToken::new(),
                closed: AtomicBool::new(false),
                tcpconn: None,
                listener: Mutex::new(None),
                handles: Mutex::new(Vec::new()),
                tx,
                rx: tokio::sync::Mutex::new(rx),
                flows: Mutex::new(Flows {
                    table: HashMap::new(),
                    fingerprint: FingerPrint::linux(),
                }),
                rules: Mutex::new(Vec::new()),
                local_addr: "127.0.0.1:29900".parse().expect("literal"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::detached_conn;
    use super::*;

    /// Serialises the tests that touch process-global state: `CONN_LIST`, the `filter/OUTPUT`
    /// chain, and `iptables_reset`, which closes *every* registered connection. Step 10.5 runs
    /// the `#[ignore]`d ones with the default (parallel) test threads, where each one's live
    /// connection and installed rule would otherwise falsify the others' assertions.
    ///
    /// It is an **async** mutex because most of those tests hold it across `.await`s (and
    /// `clippy::await_holding_lock` rightly objects to a `std` one there); the one synchronous
    /// test takes it with `blocking_lock`, which is allowed outside a runtime.
    static PRIVILEGED: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Nothing registered, nothing to close — and the global list stays usable.
    #[test]
    fn iptables_reset_without_connections_is_a_noop() {
        let _guard = PRIVILEGED.blocking_lock();
        iptables_reset();
    }

    /// A **listening** connection with a real TCP listener but no raw sockets and no iptables
    /// rules: enough for the accept loop and the close sequence, both of which are the parts of
    /// `listen` that need no privilege. Like [`detached_conn`] it stays out of `CONN_LIST`.
    async fn detached_listener_conn(bind: &str) -> TcpConn {
        let listener = Arc::new(
            tokio::net::TcpListener::bind(bind)
                .await
                .expect("bind the test listener"),
        );
        let local_addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel(MESSAGE_BACKLOG);
        TcpConn {
            inner: Arc::new(TcpConnInner {
                id: next_conn_id(),
                die: CancellationToken::new(),
                closed: AtomicBool::new(false),
                tcpconn: None,
                listener: Mutex::new(Some(listener)),
                handles: Mutex::new(Vec::new()),
                tx,
                rx: tokio::sync::Mutex::new(rx),
                flows: Mutex::new(Flows {
                    table: HashMap::new(),
                    fingerprint: FingerPrint::linux(),
                }),
                rules: Mutex::new(Vec::new()),
                local_addr,
            }),
        }
    }

    /// Starts the accept loop of a connection built by [`detached_listener_conn`].
    fn spawn_accept_loop(conn: &TcpConn) {
        let listener = lock(&conn.inner.listener)
            .clone()
            .expect("a listening connection");
        tokio::spawn(accept_loop(conn.inner.clone(), listener));
    }

    /// Waits until the flow of `peer` has its real connection recorded, and hands it back.
    async fn await_accepted(conn: &TcpConn, peer: SocketAddr) -> Arc<RealConn> {
        for _ in 0..200 {
            if let Some(real) = lock(&conn.inner.flows)
                .table
                .get(&addr::canonical(peer))
                .and_then(|flow| flow.conn.clone())
            {
                return real;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the accept loop never recorded the flow of {peer}");
    }

    /// An "installed" rule whose `iptables` binary does not exist: recording it costs nothing and
    /// deleting it fails to spawn, so no process is ever started and no privilege is needed.
    fn detached_rule() -> InstalledRule {
        InstalledRule {
            ipt: IpTables::nonexistent_for_test(Protocol::IPv4),
            rule: iptables::dial_rule(Protocol::IPv4, "10.0.0.1", "54321", "203.0.113.9", 29900),
        }
    }

    /// A closed connection reports Go's `io.EOF` from both directions.
    #[tokio::test]
    async fn a_closed_connection_reports_eof() {
        let conn = detached_conn();
        let peer: SocketAddr = "127.0.0.1:29901".parse().expect("literal");

        // A flow without a handle swallows the packet and reports it as sent, as Go does.
        assert_eq!(conn.send_to(b"hello", peer).await.expect("no handle"), 5);
        assert_eq!(lock(&conn.inner.flows).table.len(), 1);

        conn.close().expect("close");
        conn.close().expect("close is idempotent");

        let err = conn.send_to(b"hello", peer).await.expect_err("closed");
        assert_eq!(err.to_string(), "EOF");
        let mut buf = [0u8; 16];
        let err = conn.recv_from(&mut buf).await.expect_err("closed");
        assert_eq!(err.to_string(), "EOF");
    }

    /// `close_async` closes exactly like `close`, and the `Drop` that follows finds nothing left.
    #[tokio::test]
    async fn close_async_closes_once() {
        let conn = detached_conn();
        conn.inner.store_rules(vec![detached_rule()]);

        conn.close_async().await;
        assert!(conn.inner.die.is_cancelled(), "the tasks are stopped");
        assert!(lock(&conn.inner.rules).is_empty(), "the rule was deleted");

        // Both spellings of the second close run nothing at all.
        conn.close_async().await;
        conn.close().expect("close is idempotent");
    }

    /// The rules of a dial whose blocking task finishes **after** the connection was closed are
    /// removed by that task instead of being recorded on a dead connection.
    ///
    /// This is the window a cancelled `dial` leaves open: `spawn_blocking` cannot be cancelled,
    /// so the rules are appended even when the future that asked for them is gone.
    #[test]
    fn rules_installed_after_the_close_are_removed_again() {
        let conn = detached_conn();
        conn.close().expect("close");

        conn.inner.store_rules(vec![detached_rule()]);
        assert!(
            lock(&conn.inner.rules).is_empty(),
            "a closed connection records no rule: nothing would ever delete it"
        );
    }

    /// The other side of that race: rules installed while the connection is alive are recorded,
    /// and `close` deletes them.
    #[test]
    fn rules_installed_before_the_close_are_recorded() {
        let conn = detached_conn();

        conn.inner.store_rules(vec![detached_rule()]);
        assert_eq!(lock(&conn.inner.rules).len(), 1);

        conn.close().expect("close");
        assert!(lock(&conn.inner.rules).is_empty(), "close deletes them");
    }

    /// The accept loop pins every accepted connection's TTL to 1, records it as its flow's
    /// connection (which is what lifts the flow out of orphan state) and drains it.
    ///
    /// No raw socket and no privilege: this is the half of `listen` a plain kernel TCP listener
    /// already provides.
    #[tokio::test]
    async fn the_accept_loop_records_the_flow_and_lowers_the_ttl() {
        use tokio::io::AsyncWriteExt as _;

        let conn = detached_listener_conn("127.0.0.1:0").await;
        spawn_accept_loop(&conn);

        let mut client = tokio::net::TcpStream::connect(conn.local_addr())
            .await
            .expect("connect");
        let peer = client.local_addr().expect("addr");

        // Go: `conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })`.
        let real = await_accepted(&conn, peer).await;
        // Go: `if err := setTTL(tcpconn, 1); err != nil { panic(err) }`.
        assert_eq!(
            socket2::SockRef::from(real.stream())
                .ttl_v4()
                .expect("read ttl"),
            1
        );

        // Go: `go io.Copy(ioutil.Discard, tcpconn)` — more than any socket buffer holds, so this
        // only completes because the discard task keeps reading.
        let payload = vec![0x5a; 1 << 20];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.write_all(&payload),
        )
        .await
        .expect("the discard task drains the connection")
        .expect("write");

        conn.close().expect("close");
    }

    /// An IPv4 peer of a **dual-stack** listener — what `-l :29900 --tcp` accepts — is keyed by
    /// its plain IPv4 address, and `setTTL` takes Go's IPv4 branch for it: `IP_TTL` on an
    /// `AF_INET6` socket, which Linux forwards to the IPv4 option handler.
    ///
    /// Were that to fail, the accept loop would abort the process (Go panics), so it is asserted
    /// here rather than left to the signal.
    #[tokio::test]
    async fn an_ipv4_peer_of_a_dual_stack_listener_is_keyed_unmapped() {
        let conn = detached_listener_conn("[::]:0").await;
        assert!(matches!(conn.local_addr(), SocketAddr::V6(_)));
        spawn_accept_loop(&conn);

        let port = conn.local_addr().port();
        let client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let peer = client.local_addr().expect("addr");
        assert!(matches!(peer, SocketAddr::V4(_)), "an IPv4 client: {peer}");

        let real = await_accepted(&conn, peer).await;
        // `RealConn::set_ttl` picks the family from the local address, like Go's `setTTL`.
        assert!(
            addr::is_ipv4(real.stream().local_addr().expect("addr").ip()),
            "the accepted connection's local address is IPv4-mapped"
        );
        assert_eq!(
            socket2::SockRef::from(real.stream())
                .ttl_v4()
                .expect("IP_TTL on an AF_INET6 socket"),
            1
        );

        conn.close().expect("close");
    }

    /// Closing a listening connection closes the listener and every accepted connection, with the
    /// TTL restored first so the FIN survives the (absent, here) iptables rule, and empties the
    /// flow table — Go's `Close()` for the `conn.listener != nil` case.
    #[tokio::test]
    async fn closing_a_listening_connection_closes_the_listener_and_its_flows() {
        use tokio::io::AsyncReadExt as _;

        let conn = detached_listener_conn("127.0.0.1:0").await;
        let addr = conn.local_addr();
        spawn_accept_loop(&conn);

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let peer = client.local_addr().expect("addr");
        let real = await_accepted(&conn, peer).await;

        conn.close().expect("close");

        // Go: `setTTL(v.conn, 64); v.conn.Close()` for every flow, then `delete`.
        assert_eq!(
            socket2::SockRef::from(real.stream())
                .ttl_v4()
                .expect("read ttl"),
            64
        );
        assert!(lock(&conn.inner.flows).table.is_empty());
        assert!(lock(&conn.inner.listener).is_none());

        // The peer sees the connection end.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("the accepted connection is shut down")
            .expect("read");
        assert_eq!(n, 0, "end of stream");

        // And the listening socket is gone as soon as the accept loop has let go of it.
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_err() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the listener still accepts connections after close");
    }

    /// Waits until the capture loop has adopted the handshake the raw socket queued before the
    /// connect, i.e. until the flow can be written to.
    async fn await_handle(conn: &TcpConn, target: SocketAddr) {
        for _ in 0..200 {
            {
                let guard = lock(&conn.inner.flows);
                let flow = guard.table.get(&target).expect("the dialled flow");
                assert!(flow.conn.is_some(), "the dialled flow is never an orphan");
                if flow.handle.is_some() {
                    assert_eq!(flow.handle, Some(0), "the only raw handle");
                    assert_ne!(flow.seq, 0, "seq follows the peer's ACK");
                    assert_ne!(flow.ack, 0, "ack follows the peer's SYN");
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the capture loop never saw the handshake");
    }

    /// The full dial path against a local listener: the TTL is lowered, the flow picks up the
    /// handshake the raw socket queued before the connect, and the iptables rule is installed and
    /// removed again.
    ///
    /// Needs `CAP_NET_RAW` (raw socket) and `CAP_NET_ADMIN` (iptables), so it only runs where
    /// Step 10.5 runs it: on the lab host, inside a network namespace.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW and CAP_NET_ADMIN; run in Step 10.5 (netns lab)"]
    async fn dial_lowers_the_ttl_and_installs_the_rule() {
        let _guard = PRIVILEGED.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let target = listener.local_addr().expect("addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let conn = dial("tcp", &target.to_string()).await.expect("dial");
        let (_peer, _) = accepted.await.expect("join").expect("accept");

        // Go's `setTTL(tcpconn, 1)`: read it back from the socket itself.
        let real = conn.inner.tcpconn.clone().expect("dialled connection");
        let ttl = socket2::SockRef::from(real.stream())
            .ttl_v4()
            .expect("read ttl");
        assert_eq!(ttl, 1);

        await_handle(&conn, target).await;

        // The rule this connection appended is in filter/OUTPUT.
        let local = conn.local_addr();
        let rule = iptables::dial_rule(
            Protocol::IPv4,
            &addr::ip_string(local.ip()),
            &local.port().to_string(),
            &addr::ip_string(target.ip()),
            target.port(),
        );
        let ipt = IpTables::new_with_protocol(Protocol::IPv4).expect("iptables");
        assert!(ipt.exists(TABLE, CHAIN, &rule).expect("check"), "{rule:?}");
        assert_eq!(lock(&conn.inner.rules).len(), 1);

        conn.close().expect("close");
        assert!(!ipt.exists(TABLE, CHAIN, &rule).expect("check"), "{rule:?}");
        assert!(lock(&CONN_LIST).is_empty());
    }

    /// The buffer sizes of every handle, read straight off the sockets: the "before" half of the
    /// comparison [`assert_settings_reached`] makes.
    fn buffer_sizes(handles: &[Arc<RawHandle>]) -> Vec<(usize, usize)> {
        handles
            .iter()
            .map(|handle| {
                let socket = handle.socket();
                (
                    socket.recv_buffer_size().expect("SO_RCVBUF"),
                    socket.send_buffer_size().expect("SO_SNDBUF"),
                )
            })
            .collect()
    }

    /// Reads `IP_TOS`/`IPV6_TCLASS`, `SO_RCVBUF` and `SO_SNDBUF` back off **every** handle after
    /// `SetDSCP(46)`, `SetReadBuffer(4096)` and `SetWriteBuffer(4096)` have run, and checks that
    /// each one really reached that socket.
    ///
    /// The DSCP branch is where **Deviation V03** lives: `46 << 2 = 184` goes into `IP_TOS` on an
    /// `AF_INET` handle and into `IPV6_TCLASS` on an `AF_INET6` one, where Go writes the unshifted
    /// 46 — so both arms have to be executed by a caller, not just the IPv4 one.
    fn assert_settings_reached(handles: &[Arc<RawHandle>], before: &[(usize, usize)]) {
        for (handle, (rcv_before, snd_before)) in handles.iter().zip(before) {
            let socket = handle.socket();
            if handle.is_v4() {
                assert_eq!(socket.tos_v4().expect("IP_TOS"), 46 << 2);
            } else if kcptun_kcp::io::GO_RAW_IPV6_TCLASS {
                assert_eq!(socket.tclass_v6().expect("IPV6_TCLASS"), 46);
            } else {
                assert_eq!(socket.tclass_v6().expect("IPV6_TCLASS"), 46 << 2);
            }
            // Linux stores twice what `SO_{RCV,SND}BUF` was given (the second half is the
            // kernel's own bookkeeping) and never goes below its floor, so the exact value is the
            // kernel's business; what matters is that the option reached *this* handle. Hence the
            // comparison with the pre-setter value rather than a bound: 2 * 4096 = 8192 is far
            // below the default the socket starts with, so the read-back value must move.
            let rcv = socket.recv_buffer_size().expect("SO_RCVBUF");
            let snd = socket.send_buffer_size().expect("SO_SNDBUF");
            assert!(rcv >= 4096, "SO_RCVBUF is below what was asked for: {rcv}");
            assert!(snd >= 4096, "SO_SNDBUF is below what was asked for: {snd}");
            assert_ne!(
                rcv, *rcv_before,
                "SO_RCVBUF never reached the raw socket (still at its default)"
            );
            assert_ne!(
                snd, *snd_before,
                "SO_SNDBUF never reached the raw socket (still at its default)"
            );
        }
    }

    /// The port of Go's `TestSettings`: the three socket-option setters against live connections,
    /// where they reach real raw sockets instead of the empty handle list the unprivileged
    /// `the_setters_of_a_handleless_connection_succeed` exercises.
    ///
    /// Go only checks that none of them returns an error, which a setter that silently applied to
    /// nothing would also pass. This reads every option back off every handle — the buffer sizes
    /// against the values the same handle had a moment earlier, so a setter that reached nothing
    /// fails here.
    ///
    /// It runs the setters against **both** shapes a `TcpConn` comes in, because only the second
    /// has more than one handle and only the second has an `AF_INET6` one:
    ///  * a `dial`, whose single handle is the IPv4 socket of the dialled flow, and
    ///  * a wildcard `listen`, which opens one handle per interface address — loopback, IPv6
    ///    included — so the `IPV6_TCLASS` arm of `RawHandle::set_dscp` is executed and
    ///    **Deviation V03** (the code point written shifted, `46 << 2 = 184`, where Go writes the
    ///    unshifted 46) is pinned on a live socket rather than only asserted in the IPv4 arm.
    ///
    /// The `filter/OUTPUT` chain is compared against its pre-test state at the end, as in
    /// `dial_lowers_the_ttl_and_installs_the_rule`: both halves install rules.
    ///
    /// Needs `CAP_NET_RAW` and `CAP_NET_ADMIN` (`dial` installs a rule), so it runs in Step 10.5's
    /// network namespace with the other privileged tests.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW and CAP_NET_ADMIN; run in Step 10.5 (netns lab)"]
    async fn test_settings() {
        let _guard = PRIVILEGED.lock().await;
        let chain_before = output_chain();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let target = listener.local_addr().expect("addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let conn = dial("tcp", &target.to_string()).await.expect("dial");
        let (_peer, _) = accepted.await.expect("join").expect("accept");

        // The buffer sizes *before* the setters run. Reading them back afterwards and only
        // checking `>= 4096` would be the very hole this test exists to close: the socket is
        // created with `net.core.{r,w}mem_default` (212992 on the lab host), so that bound holds
        // on an untouched handle and a setter that reached nothing would pass.
        let handles = conn.inner.handle_snapshot();
        assert_eq!(handles.len(), 1, "a dialled connection has one raw socket");
        let before = buffer_sizes(&handles);

        // Go: `conn.SetDSCP(46)`, `conn.SetReadBuffer(4096)`, `conn.SetWriteBuffer(4096)`.
        conn.set_dscp(46).expect("SetDSCP");
        conn.set_read_buffer(4096).expect("SetReadBuffer");
        conn.set_write_buffer(4096).expect("SetWriteBuffer");
        assert_settings_reached(&handles, &before);

        conn.close().expect("close");
        assert!(lock(&CONN_LIST).is_empty());

        // The same three setters against a wildcard `listen`, which is the only configuration
        // with more than one handle and the only one with an `AF_INET6` handle — so this, and
        // not the dial above, is what executes the IPv6 arm of `RawHandle::set_dscp`.
        let conn = listen("tcp", &format!(":{LISTEN_PORT}"))
            .await
            .expect("listen");
        let handles = conn.inner.handle_snapshot();
        assert!(
            handles.len() > 1,
            "a wildcard listen captures on every interface address; got {} handle(s)",
            handles.len()
        );
        assert!(
            handles.iter().any(|handle| !handle.is_v4()),
            "no AF_INET6 handle, so the IPV6_TCLASS branch this test exists for never ran — \
             the namespace needs an IPv6 address (`lo` up gives it `::1`)"
        );
        let before = buffer_sizes(&handles);

        conn.set_dscp(46).expect("SetDSCP");
        conn.set_read_buffer(4096).expect("SetReadBuffer");
        conn.set_write_buffer(4096).expect("SetWriteBuffer");
        assert_settings_reached(&handles, &before);

        conn.close().expect("close");
        assert_eq!(output_chain(), chain_before, "a rule survived the close");
        assert!(lock(&CONN_LIST).is_empty());
    }

    /// Everything `iptables -S OUTPUT` lists, for the before/after comparison below.
    fn output_chain() -> String {
        let out = std::process::Command::new("iptables")
            .args(["-t", TABLE, "-S", CHAIN])
            .output()
            .expect("iptables -S");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A `dial` future dropped before it returns leaves nothing behind — no `filter/OUTPUT` rule,
    /// no entry in the global list.
    ///
    /// `tokio::time::timeout` around `dial` is what a client startup naturally writes,
    /// and the drop can land on the `spawn_blocking` that appends the rules: that task cannot be
    /// cancelled, so the rules are installed with no `TcpConn` in sight, and only `store_rules`
    /// noticing the close removes them again.
    ///
    /// Needs `CAP_NET_RAW` and `CAP_NET_ADMIN`, and a chain nothing else is editing, so it runs
    /// in Step 10.5's network namespace with the other privileged tests.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW and CAP_NET_ADMIN; run in Step 10.5 (netns lab)"]
    async fn a_cancelled_dial_leaves_nothing_behind() {
        let _guard = PRIVILEGED.lock().await;
        use std::time::Duration;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let target = listener.local_addr().expect("addr");
        let accepted = tokio::spawn(async move { listener.accept().await });
        let before = output_chain();

        // A timeout short enough to land inside the dial. Should it ever be too long, the dial
        // succeeds and the connection is closed by hand: the assertions below hold either way.
        let outcome =
            tokio::time::timeout(Duration::from_micros(500), dial("tcp", &target.to_string()))
                .await;
        if let Ok(result) = outcome {
            result.expect("dial").close().expect("close");
        }
        // The cancellation usually lands *before* the real TCP connect, so nothing ever reaches
        // the listener and the accept would block for the rest of the process's life. Found the
        // first time this test was run (Step 10.5, lab-x86-3): it hung the whole `--ignored` run,
        // because the other privileged tests were queued behind this one's `PRIVILEGED` guard.
        accepted.abort();
        let _ = accepted.await;

        // The blocking task may still be appending; give it until it has cleaned up after itself.
        for _ in 0..100 {
            if lock(&CONN_LIST).is_empty() && output_chain() == before {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            lock(&CONN_LIST).is_empty(),
            "the connection is still listed"
        );
        assert_eq!(output_chain(), before, "a rule survived the cancelled dial");
    }

    /// The kernel's `TcpExtPAWSEstab` counter: segments an established connection discarded
    /// because their timestamp looked older than the last one it accepted.
    fn paws_estab() -> u64 {
        let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
        let mut lines = text.lines();
        while let Some(head) = lines.next() {
            let Some(values) = lines.next() else { break };
            if !head.starts_with("TcpExt:") {
                continue;
            }
            let Some(column) = head.split_whitespace().position(|f| f == "PAWSEstab") else {
                continue;
            };
            return values
                .split_whitespace()
                .nth(column)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
        0
    }

    /// Both directions of the data path, against an ordinary kernel TCP peer — the Rust
    /// counterpart of Go's `TestDialTCPStream`.
    ///
    /// This is what "fake TCP" means: the segment `send_to` crafts continues the real
    /// connection's sequence space, so the peer's own stack accepts it as data and hands it to
    /// the application — and the data the peer's stack sends back is picked up from the raw
    /// socket and delivered by `recv_from`.
    ///
    /// Needs `CAP_NET_RAW` only; the iptables rules are not what makes this work (the peer's
    /// acknowledgements for data our kernel never sent are answered with segments that the TTL
    /// of 1 already confines to this host).
    ///
    /// # PAWS
    ///
    /// Run it with `sysctl -w net.ipv4.tcp_timestamps=0` in the test's network namespace.
    ///
    /// The crafted segments carry a TSval from a boot time that Deviation **V10** (upstream
    /// tcpraw `cbf9635`) places a uniformly random 0–30 days in the past, while the *kernel's*
    /// handshake on the same 5-tuple used its own clock. When our random offset lands below the
    /// host's uptime, the peer's RFC 7323 PAWS check reads the crafted segment as ancient and
    /// discards it — measured on a host up for 21 days: 3 of 6 runs, with `TcpExtPAWSEstab`
    /// rising each time, and 6 of 6 passing with timestamps off.
    ///
    /// **This does not affect kcptun.** A tcpraw peer reads its datagrams from its *raw* socket,
    /// which the kernel fills before TCP ever looks at the segment, so PAWS cannot touch that
    /// path; only a plain kernel TCP peer, which nothing but this test and Go's own
    /// `TestDialTCPStream` uses, is affected — and upstream Go is affected identically.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW (and tcp_timestamps=0, see PAWS); run in Step 10.5 (netns lab)"]
    async fn test_dial_tcp_stream() {
        let _guard = PRIVILEGED.lock().await;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let target = listener.local_addr().expect("addr");
        let accepted = tokio::spawn(async move { listener.accept().await });

        let conn = dial("tcp", &target.to_string()).await.expect("dial");
        let (mut peer, _) = accepted.await.expect("join").expect("accept");
        await_handle(&conn, target).await;

        // Write path: the peer's kernel cannot tell the crafted segment from real TCP data.
        let paws_before = paws_estab();
        let sent = conn.send_to(b"from tcpraw", target).await.expect("send");
        assert_eq!(sent, 11);
        let mut buf = [0u8; 64];
        let n = match tokio::time::timeout(TIMEOUT, peer.read(&mut buf)).await {
            Ok(result) => result.expect("read"),
            Err(_) => {
                let dropped = paws_estab().saturating_sub(paws_before);
                assert_eq!(
                    dropped, 0,
                    "the peer's kernel discarded {dropped} segment(s) on the PAWS check; \
                     see this test's docs — run it with net.ipv4.tcp_timestamps=0"
                );
                panic!("the peer never received the crafted segment");
            }
        };
        assert_eq!(&buf[..n], b"from tcpraw");

        // Read path: the peer's own segment is captured and delivered as a datagram.
        peer.write_all(b"to tcpraw").await.expect("write");
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(TIMEOUT, conn.recv_from(&mut buf))
            .await
            .expect("the capture loop delivers the payload")
            .expect("recv");
        assert_eq!(&buf[..n], b"to tcpraw");
        assert_eq!(from, target);

        conn.close().expect("close");
    }

    /// The port a listening test binds. Fixed, because a tcpraw listener cannot use an ephemeral
    /// one: Go filters the capture on the **resolved** port and writes `--sport <resolved port>`
    /// into the rule, so a `:0` listen would watch port 0. Inside tools/lab/README.md's tcpraw range.
    const LISTEN_PORT: u16 = 29903;

    /// A wildcard `listen` opens one raw handle per interface address, binds a dual-stack TCP
    /// listener, installs the `--sport` rule and takes it away again on close.
    ///
    /// Needs `CAP_NET_RAW` and `CAP_NET_ADMIN`, and a `filter/OUTPUT` chain nothing else is
    /// editing, so it runs where Step 10.5 runs: on the lab host, inside a network namespace.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW and CAP_NET_ADMIN; run in Step 10.5 (netns lab)"]
    async fn listen_opens_a_handle_per_interface_and_installs_the_rule() {
        let _guard = PRIVILEGED.lock().await;
        let before = output_chain();

        let conn = listen("tcp", &format!(":{LISTEN_PORT}"))
            .await
            .expect("listen");

        // Go: `net.ListenTCP("tcp", &TCPAddr{IP: nil, Port: …})` — the dual-stack wildcard.
        let local = conn.local_addr();
        assert!(matches!(local, SocketAddr::V6(_)), "{local}");
        assert_eq!(local.port(), LISTEN_PORT);

        // One handle per interface address the kernel let us bind, and never fewer than the
        // loopback one.
        let handles = lock(&conn.inner.handles).len();
        assert!(handles >= 1, "no raw handle");
        assert!(
            handles <= iface::interface_addrs().expect("getifaddrs").len(),
            "more handles than interface addresses"
        );

        // Go's `Listen` rule: no peer, just the source port.
        let rule = iptables::listen_rule(Protocol::IPv4, LISTEN_PORT);
        let ipt = IpTables::new_with_protocol(Protocol::IPv4).expect("iptables");
        assert!(ipt.exists(TABLE, CHAIN, &rule).expect("check"), "{rule:?}");
        assert_eq!(lock(&conn.inner.rules).len(), 2, "one rule per protocol");

        // An ordinary TCP client is accepted, pinned to TTL 1 and recorded as its flow's
        // connection.
        let client = tokio::net::TcpStream::connect(("127.0.0.1", LISTEN_PORT))
            .await
            .expect("connect");
        let peer = client.local_addr().expect("addr");
        let real = await_accepted(&conn, peer).await;
        assert_eq!(
            socket2::SockRef::from(real.stream())
                .ttl_v4()
                .expect("read ttl"),
            1
        );

        conn.close().expect("close");
        assert!(!ipt.exists(TABLE, CHAIN, &rule).expect("check"), "{rule:?}");
        assert_eq!(output_chain(), before, "a rule survived the close");
        assert!(lock(&CONN_LIST).is_empty());
    }

    /// A `listen` on one address opens exactly one raw handle, bound to that address.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW and CAP_NET_ADMIN; run in Step 10.5 (netns lab)"]
    async fn listen_on_one_address_opens_one_handle() {
        let _guard = PRIVILEGED.lock().await;
        let before = output_chain();

        let conn = listen("tcp", &format!("127.0.0.1:{LISTEN_PORT}"))
            .await
            .expect("listen");
        assert_eq!(
            conn.local_addr(),
            format!("127.0.0.1:{LISTEN_PORT}")
                .parse::<SocketAddr>()
                .expect("literal")
        );

        let handles = lock(&conn.inner.handles);
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles[0].local_ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().expect("literal")
        );
        assert!(handles[0].is_v4());
        drop(handles);

        conn.close().expect("close");
        assert_eq!(output_chain(), before);
    }

    /// The Rust counterpart of Go's `TestDialToTCPPacket`: a dialled tcpraw connection and a
    /// listening one, talking to each other over crafted segments only.
    ///
    /// This is the whole of Step 10.3 end to end — per-interface capture, the accept loop that
    /// makes the server's flow deliverable, and `sendto` on a bound raw socket — and the shape
    /// the client and server binaries use, now that Step 10.4 has wired them up.
    ///
    /// Needs `CAP_NET_RAW` and `CAP_NET_ADMIN` (the listener's rule must be in place, or the
    /// host's kernel answers the crafted segments with RSTs of its own).
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW and CAP_NET_ADMIN; run in Step 10.5 (netns lab)"]
    async fn test_dial_to_tcp_packet() {
        let _guard = PRIVILEGED.lock().await;
        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let server = listen("tcp", &format!(":{LISTEN_PORT}"))
            .await
            .expect("listen");
        let target: SocketAddr = format!("127.0.0.1:{LISTEN_PORT}").parse().expect("literal");

        let client = dial("tcp", &target.to_string()).await.expect("dial");
        await_handle(&client, target).await;

        // Client → server.
        assert_eq!(client.send_to(b"abc", target).await.expect("send"), 3);
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(TIMEOUT, server.recv_from(&mut buf))
            .await
            .expect("the server's capture loop delivers the payload")
            .expect("recv");
        assert_eq!(&buf[..n], b"abc");
        assert_eq!(from, client.local_addr());

        // Server → client, through `sendto` on the bound raw handle.
        assert_eq!(server.send_to(b"cba", from).await.expect("send"), 3);
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
            .await
            .expect("the client's capture loop delivers the payload")
            .expect("recv");
        assert_eq!(&buf[..n], b"cba");
        assert_eq!(from, target);

        client.close().expect("close");
        server.close().expect("close");
    }
}
