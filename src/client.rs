//! The client of a policy daemon.
//!
//! The check answers from the table in this process. A daemon address is
//! optional. When nothing accepts, the connect returns inside
//! [`CONNECT_TIMEOUT`] and the table's line is what the caller sees.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// How long a connect may sit when no daemon accepts.
///
/// A refused loopback port returns at once. `192.0.2.1` (TEST-NET-1, RFC
/// 5737) does not answer: a 400 ms socket timeout returned at 400 ms on
/// this host. 300 ms is long enough to tell those apart and shorter than
/// the old one-second judgment wait, so a missing daemon cannot hold the
/// answer for that second.
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// Connect to `addr` and stop at [`CONNECT_TIMEOUT`].
///
/// The stream is not read. A daemon that accepts and writes nothing would
/// otherwise hold the caller past the connect timeout. The table answers
/// either way.
pub fn probe_daemon(addr: SocketAddr) -> std::io::Result<()> {
    let _stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Instant;

    /// `192.0.2.1` is TEST-NET-1 (RFC 5737) and does not answer. A 400 ms
    /// socket timeout returned at 400 ms on this host, so a wait past
    /// [`CONNECT_TIMEOUT`] is the client holding the answer.
    #[test]
    fn a_blackhole_connect_returns_inside_the_timeout() {
        let addr: SocketAddr = "192.0.2.1:81".parse().unwrap();
        let started = Instant::now();
        let result = probe_daemon(addr);
        let elapsed = started.elapsed();
        assert!(result.is_err(), "{result:?}");
        assert!(
            elapsed >= Duration::from_millis(200),
            "returned too fast to be the timeout: {elapsed:?}"
        );
        assert!(
            elapsed <= CONNECT_TIMEOUT + Duration::from_millis(80),
            "waited past the connect timeout: {elapsed:?}"
        );
    }
}
