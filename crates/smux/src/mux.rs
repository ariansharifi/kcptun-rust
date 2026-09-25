//! Session configuration, its verification and the two session constructors (port of `mux.go`).
//!
//! [`verify_config`]'s error texts are the ones kcptun prints verbatim.

use std::time::Duration;

use crate::conn::SmuxConn;
use crate::error::Error;
use crate::session::Session;

/// Largest `max_frame_size` [`verify_config`] accepts. Go writes the literal 65535; it is the
/// largest value the frame header's `u16` length field can describe.
// Go: smux@v1.5.55 mux.go:VerifyConfig()
pub const MAX_FRAME_SIZE_LIMIT: isize = 65535;

/// Largest buffer size [`verify_config`] accepts (`math.MaxInt32`).
// Go: smux@v1.5.55 mux.go:VerifyConfig()
pub const MAX_BUFFER_LIMIT: isize = i32::MAX as isize;

/// Tuning of one smux session.
///
/// Go's sizes are `int`, so they are [`isize`] here and can be negative, which
/// [`verify_config`] rejects exactly as Go does.
///
/// **Durations.** Go's `time.Duration` is signed. A negative `KeepAliveInterval` passes
/// `VerifyConfig` (it is neither zero nor larger than the timeout) and then makes `keepalive()`
/// panic in `time.NewTicker`; the golden vector `config/verify/keepalive_interval=-1s` records
/// that. [`Duration`] is unsigned, so the state is unrepresentable here and the CLI layer
/// (step 08) decides what a negative `-keepalive` means.
// Go: smux@v1.5.55 mux.go:Config
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Config {
    /// Protocol version; 1 and 2 are supported.
    pub version: isize,
    /// Disables the keepalive task (and its two checks in [`verify_config`]).
    pub keep_alive_disabled: bool,
    /// How often a `cmdNOP` is sent to the peer.
    pub keep_alive_interval: Duration,
    /// How long the session survives without any frame arriving.
    pub keep_alive_timeout: Duration,
    /// Largest payload of a frame sent to the peer.
    pub max_frame_size: isize,
    /// Session-wide receive token bucket (never on the wire).
    pub max_receive_buffer: isize,
    /// Per-stream receive window advertised in `cmdUPD` (protocol version 2).
    pub max_stream_buffer: isize,
}

/// The configuration smux uses when the caller passes none.
// Go: smux@v1.5.55 mux.go:DefaultConfig()
pub fn default_config() -> Config {
    Config {
        version: 1,
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_secs(10),
        keep_alive_timeout: Duration::from_secs(30),
        max_frame_size: 32768,
        max_receive_buffer: 4194304,
        max_stream_buffer: 65536,
    }
}

impl Default for Config {
    fn default() -> Self {
        default_config()
    }
}

/// Why a [`Config`] was rejected. The messages are Go's, word for word.
// Go: smux@v1.5.55 mux.go:VerifyConfig()
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ConfigError {
    /// `version` is neither 1 nor 2.
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    /// `keep_alive_interval` is zero while keepalive is enabled.
    #[error("keep-alive interval must be positive")]
    KeepAliveInterval,
    /// `keep_alive_timeout` is shorter than `keep_alive_interval`. (Go's text says "larger",
    /// but the check accepts equal values.)
    #[error("keep-alive timeout must be larger than keep-alive interval")]
    KeepAliveTimeout,
    /// `max_frame_size` is zero or negative.
    #[error("max frame size must be positive")]
    FrameSizeNotPositive,
    /// `max_frame_size` exceeds [`MAX_FRAME_SIZE_LIMIT`].
    #[error("max frame size must not be larger than 65535")]
    FrameSizeTooLarge,
    /// `max_receive_buffer` is zero or negative.
    #[error("max receive buffer must be positive")]
    ReceiveBufferNotPositive,
    /// `max_receive_buffer` exceeds [`MAX_BUFFER_LIMIT`].
    #[error("max receive buffer cannot be larger than 2147483647")]
    ReceiveBufferTooLarge,
    /// `max_stream_buffer` is zero or negative.
    #[error("max stream buffer must be positive")]
    StreamBufferNotPositive,
    /// `max_stream_buffer` exceeds `max_receive_buffer`.
    #[error("max stream buffer must not be larger than max receive buffer")]
    StreamBufferAboveReceiveBuffer,
    /// `max_stream_buffer` exceeds [`MAX_BUFFER_LIMIT`].
    ///
    /// Unreachable, in Go as well: it would need
    /// `max_receive_buffer >= max_stream_buffer > MAX_BUFFER_LIMIT`, which
    /// [`ConfigError::ReceiveBufferTooLarge`] rejects first. Kept so the port has every branch
    /// of `VerifyConfig` (golden vector `config/verify/stream_buffer=maxint32+1`).
    #[error("max stream buffer cannot be larger than 2147483647")]
    StreamBufferTooLarge,
}

/// Checks a configuration, in Go's order: the first failing rule decides the error.
// Go: smux@v1.5.55 mux.go:VerifyConfig()
pub fn verify_config(config: &Config) -> Result<(), ConfigError> {
    if !(config.version == 1 || config.version == 2) {
        return Err(ConfigError::UnsupportedVersion);
    }
    if !config.keep_alive_disabled {
        if config.keep_alive_interval.is_zero() {
            return Err(ConfigError::KeepAliveInterval);
        }
        if config.keep_alive_timeout < config.keep_alive_interval {
            return Err(ConfigError::KeepAliveTimeout);
        }
    }
    if config.max_frame_size <= 0 {
        return Err(ConfigError::FrameSizeNotPositive);
    }
    if config.max_frame_size > MAX_FRAME_SIZE_LIMIT {
        return Err(ConfigError::FrameSizeTooLarge);
    }
    if config.max_receive_buffer <= 0 {
        return Err(ConfigError::ReceiveBufferNotPositive);
    }
    if config.max_receive_buffer > MAX_BUFFER_LIMIT {
        return Err(ConfigError::ReceiveBufferTooLarge);
    }
    if config.max_stream_buffer <= 0 {
        return Err(ConfigError::StreamBufferNotPositive);
    }
    if config.max_stream_buffer > config.max_receive_buffer {
        return Err(ConfigError::StreamBufferAboveReceiveBuffer);
    }
    if config.max_stream_buffer > MAX_BUFFER_LIMIT {
        return Err(ConfigError::StreamBufferTooLarge);
    }
    Ok(())
}

/// Starts a session as the *server* side: it accepts streams the peer opens, and the streams it
/// opens itself get the even ids 2, 4, 6, …
///
/// `config` of `None` is Go's `nil`, i.e. [`default_config`]. The tasks are spawned on the
/// current tokio runtime, so this must be called from inside one.
// Go: smux@v1.5.55 mux.go:Server()
pub fn server<C: SmuxConn>(conn: C, config: Option<Config>) -> Result<Session<C>, Error> {
    let config = config.unwrap_or_else(default_config);
    verify_config(&config)?;
    Ok(Session::new(config, conn, false))
}

/// Starts a session as the *client* side: the streams it opens get the odd ids 3, 5, 7, …
///
/// `config` of `None` is Go's `nil`, i.e. [`default_config`]. The tasks are spawned on the
/// current tokio runtime, so this must be called from inside one.
// Go: smux@v1.5.55 mux.go:Client()
pub fn client<C: SmuxConn>(conn: C, config: Option<Config>) -> Result<Session<C>, Error> {
    let config = config.unwrap_or_else(default_config);
    verify_config(&config)?;
    Ok(Session::new(config, conn, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_go() {
        let c = default_config();
        assert_eq!(c, Config::default());
        assert_eq!(c.version, 1);
        assert!(!c.keep_alive_disabled);
        assert_eq!(c.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(c.keep_alive_timeout, Duration::from_secs(30));
        assert_eq!(c.max_frame_size, 32768);
        assert_eq!(c.max_receive_buffer, 4194304);
        assert_eq!(c.max_stream_buffer, 65536);
        assert_eq!(verify_config(&c), Ok(()));
    }

    #[test]
    fn version_must_be_1_or_2() {
        let mut c = default_config();
        for v in [1, 2] {
            c.version = v;
            assert_eq!(verify_config(&c), Ok(()));
        }
        for v in [-1, 0, 3, 100] {
            c.version = v;
            assert_eq!(verify_config(&c), Err(ConfigError::UnsupportedVersion));
        }
    }

    #[test]
    fn keepalive_checks_are_skipped_when_disabled() {
        let mut c = default_config();
        c.keep_alive_interval = Duration::ZERO;
        assert_eq!(verify_config(&c), Err(ConfigError::KeepAliveInterval));
        c.keep_alive_disabled = true;
        c.keep_alive_timeout = Duration::ZERO;
        assert_eq!(verify_config(&c), Ok(()));
    }

    #[test]
    fn keepalive_timeout_may_equal_the_interval() {
        let mut c = default_config();
        c.keep_alive_interval = Duration::from_secs(10);
        c.keep_alive_timeout = Duration::from_secs(10);
        assert_eq!(verify_config(&c), Ok(()));
        c.keep_alive_interval = Duration::from_secs(30);
        assert_eq!(verify_config(&c), Err(ConfigError::KeepAliveTimeout));
    }

    #[test]
    fn buffer_and_frame_size_bounds() {
        let mut c = default_config();
        for bad in [0, -1] {
            c.max_frame_size = bad;
            assert_eq!(verify_config(&c), Err(ConfigError::FrameSizeNotPositive));
        }
        c.max_frame_size = MAX_FRAME_SIZE_LIMIT;
        assert_eq!(verify_config(&c), Ok(()));
        c.max_frame_size = MAX_FRAME_SIZE_LIMIT + 1;
        assert_eq!(verify_config(&c), Err(ConfigError::FrameSizeTooLarge));

        let mut c = default_config();
        for bad in [0, -1] {
            c.max_receive_buffer = bad;
            assert_eq!(
                verify_config(&c),
                Err(ConfigError::ReceiveBufferNotPositive)
            );
        }
        c.max_receive_buffer = MAX_BUFFER_LIMIT;
        assert_eq!(verify_config(&c), Ok(()));
        // Unrepresentable where isize is 32 bits, exactly as Go's int would be.
        if let Some(too_large) = MAX_BUFFER_LIMIT.checked_add(1) {
            c.max_receive_buffer = too_large;
            assert_eq!(verify_config(&c), Err(ConfigError::ReceiveBufferTooLarge));
        }

        let mut c = default_config();
        for bad in [0, -1] {
            c.max_stream_buffer = bad;
            assert_eq!(verify_config(&c), Err(ConfigError::StreamBufferNotPositive));
        }
        c.max_stream_buffer = c.max_receive_buffer;
        assert_eq!(verify_config(&c), Ok(()));
        c.max_stream_buffer = c.max_receive_buffer + 1;
        assert_eq!(
            verify_config(&c),
            Err(ConfigError::StreamBufferAboveReceiveBuffer)
        );
    }

    // The receive-buffer bound fires first, so StreamBufferTooLarge cannot be produced by any
    // configuration (same in Go).
    #[test]
    fn stream_buffer_limit_branch_is_unreachable() {
        let mut c = default_config();
        c.max_receive_buffer = MAX_BUFFER_LIMIT;
        if let Some(too_large) = MAX_BUFFER_LIMIT.checked_add(1) {
            c.max_stream_buffer = too_large;
            assert_eq!(
                verify_config(&c),
                Err(ConfigError::StreamBufferAboveReceiveBuffer)
            );
        }
        assert_eq!(
            ConfigError::StreamBufferTooLarge.to_string(),
            "max stream buffer cannot be larger than 2147483647"
        );
    }
}
