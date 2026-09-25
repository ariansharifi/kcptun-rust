//! The smux configuration kcptun builds from its flags.
//!
//! Go: `kcptun/std/smuxcfg.go:BuildSmuxConfig`, which fills `smux.DefaultConfig()` from the
//! command line and runs `smux.VerifyConfig`.
//!
//! [`SmuxConfig`] is a plain value type rather than `kcptun_smux`'s own configuration, so that
//! the flag handling and its verification stay independent of the smux crate's API. Step 09.1
//! added the one-way mapping the binaries need, `From<SmuxConfig> for kcptun_smux::Config`.

use std::time::Duration;

/// A smux session configuration.
// Go: smux@v1.5.55 mux.go:Config
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmuxConfig {
    /// smux protocol version, 1 or 2.
    pub version: i64,
    /// Disables keepalive frames entirely (kcptun never sets it).
    pub keep_alive_disabled: bool,
    /// How often a NOP frame is sent.
    pub keep_alive_interval: Duration,
    /// How long the session may stay silent before it is closed.
    pub keep_alive_timeout: Duration,
    /// Largest frame written to the peer.
    pub max_frame_size: i64,
    /// Overall de-multiplexing buffer.
    pub max_receive_buffer: i64,
    /// Per-stream receive buffer (smux v2+).
    pub max_stream_buffer: i64,
}

impl Default for SmuxConfig {
    // Go: smux@v1.5.55 mux.go:DefaultConfig
    fn default() -> Self {
        SmuxConfig {
            version: 1,
            keep_alive_disabled: false,
            keep_alive_interval: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(30),
            max_frame_size: 32768,
            max_receive_buffer: 4194304,
            max_stream_buffer: 65536,
        }
    }
}

/// Why a smux configuration was rejected. The texts are smux's own (porting guide §4).
// Go: smux@v1.5.55 mux.go:VerifyConfig
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SmuxConfigError {
    #[error("unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[error("keep-alive interval must be positive")]
    KeepAliveIntervalNotPositive,
    #[error("keep-alive timeout must be larger than keep-alive interval")]
    KeepAliveTimeoutTooSmall,
    #[error("max frame size must be positive")]
    MaxFrameSizeNotPositive,
    #[error("max frame size must not be larger than 65535")]
    MaxFrameSizeTooLarge,
    #[error("max receive buffer must be positive")]
    MaxReceiveBufferNotPositive,
    #[error("max receive buffer cannot be larger than 2147483647")]
    MaxReceiveBufferTooLarge,
    #[error("max stream buffer must be positive")]
    MaxStreamBufferNotPositive,
    #[error("max stream buffer must not be larger than max receive buffer")]
    MaxStreamBufferLargerThanReceiveBuffer,
    #[error("max stream buffer cannot be larger than 2147483647")]
    MaxStreamBufferTooLarge,
}

impl SmuxConfig {
    /// Checks the configuration in smux's order, so the error a user sees is the one Go prints.
    // Go: smux@v1.5.55 mux.go:VerifyConfig
    pub fn verify(&self) -> Result<(), SmuxConfigError> {
        use SmuxConfigError as E;
        if !(self.version == 1 || self.version == 2) {
            return Err(E::UnsupportedProtocolVersion);
        }
        if !self.keep_alive_disabled {
            if self.keep_alive_interval.is_zero() {
                return Err(E::KeepAliveIntervalNotPositive);
            }
            if self.keep_alive_timeout < self.keep_alive_interval {
                return Err(E::KeepAliveTimeoutTooSmall);
            }
        }
        if self.max_frame_size <= 0 {
            return Err(E::MaxFrameSizeNotPositive);
        }
        if self.max_frame_size > 65535 {
            return Err(E::MaxFrameSizeTooLarge);
        }
        if self.max_receive_buffer <= 0 {
            return Err(E::MaxReceiveBufferNotPositive);
        }
        if self.max_receive_buffer > i64::from(i32::MAX) {
            return Err(E::MaxReceiveBufferTooLarge);
        }
        if self.max_stream_buffer <= 0 {
            return Err(E::MaxStreamBufferNotPositive);
        }
        if self.max_stream_buffer > self.max_receive_buffer {
            return Err(E::MaxStreamBufferLargerThanReceiveBuffer);
        }
        if self.max_stream_buffer > i64::from(i32::MAX) {
            return Err(E::MaxStreamBufferTooLarge);
        }
        Ok(())
    }
}

/// Builds the smux configuration from the `-smuxver`, `-smuxbuf`, `-streambuf`, `-framesize`
/// and `-keepalive` flags and verifies it.
///
/// `KeepAliveTimeout` stays at smux's default of 30 s, which is what Go gets by starting from
/// `smux.DefaultConfig()`. Go returns the configuration *and* the error; both call sites
/// (`client/main.go`, `server/main.go`) treat a non-nil error as fatal, so this returns a
/// `Result` instead.
// Go: kcptun/std/smuxcfg.go:BuildSmuxConfig
pub fn build_smux_config(
    version: i64,
    max_receive_buffer: i64,
    max_stream_buffer: i64,
    max_frame_size: i64,
    keep_alive_seconds: i64,
) -> Result<SmuxConfig, SmuxConfigError> {
    let cfg = SmuxConfig {
        version,
        max_receive_buffer,
        max_stream_buffer,
        max_frame_size,
        // Go: time.Duration(keepAliveSeconds) * time.Second. A negative count would make a
        // negative Duration, which `is_zero` does not catch; Duration is unsigned here, so the
        // value is clamped to zero and hits "keep-alive interval must be positive" instead.
        // Deviation V12: Go's VerifyConfig lets a negative interval through and panics later in
        // time.NewTicker; this reports it at startup with smux's own text.
        keep_alive_interval: Duration::from_secs(keep_alive_seconds.max(0) as u64),
        ..SmuxConfig::default()
    };
    cfg.verify()?;
    Ok(cfg)
}

/// The configuration `smux.Server`/`smux.Client` is handed, which in Go *is* the value
/// `BuildSmuxConfig` returns.
// Go: kcptun/std/smuxcfg.go:BuildSmuxConfig — the *smux.Config it returns
impl From<SmuxConfig> for kcptun_smux::Config {
    fn from(cfg: SmuxConfig) -> kcptun_smux::Config {
        kcptun_smux::Config {
            version: cfg.version as isize,
            keep_alive_disabled: cfg.keep_alive_disabled,
            keep_alive_interval: cfg.keep_alive_interval,
            keep_alive_timeout: cfg.keep_alive_timeout,
            max_frame_size: cfg.max_frame_size as isize,
            max_receive_buffer: cfg.max_receive_buffer as isize,
            max_stream_buffer: cfg.max_stream_buffer as isize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smux_crate_config_is_the_same_values() {
        // kcptun's server defaults, mapped into the configuration smux itself verifies.
        let cfg = build_smux_config(2, 4194304, 2097152, 8192, 10).expect("kcptun defaults");
        let smux: kcptun_smux::Config = cfg.into();
        assert_eq!(smux.version, 2);
        assert!(!smux.keep_alive_disabled);
        assert_eq!(smux.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(smux.keep_alive_timeout, Duration::from_secs(30));
        assert_eq!(smux.max_frame_size, 8192);
        assert_eq!(smux.max_receive_buffer, 4194304);
        assert_eq!(smux.max_stream_buffer, 2097152);
        kcptun_smux::verify_config(&smux).expect("smux verifies what this port verified");
    }

    #[test]
    fn defaults_match_go() {
        let cfg = SmuxConfig::default();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(cfg.keep_alive_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_frame_size, 32768);
        assert_eq!(cfg.max_receive_buffer, 4194304);
        assert_eq!(cfg.max_stream_buffer, 65536);
        cfg.verify().expect("smux's own defaults verify");
    }

    #[test]
    fn build_uses_kcptun_defaults() {
        // client/main.go and server/main.go defaults: smuxver 2, smuxbuf 4 MiB, streambuf 2 MiB,
        // framesize 8192, keepalive 10 s.
        let cfg = build_smux_config(2, 4194304, 2097152, 8192, 10).expect("kcptun defaults");
        assert_eq!(
            cfg,
            SmuxConfig {
                version: 2,
                keep_alive_disabled: false,
                keep_alive_interval: Duration::from_secs(10),
                keep_alive_timeout: Duration::from_secs(30),
                max_frame_size: 8192,
                max_receive_buffer: 4194304,
                max_stream_buffer: 2097152,
            }
        );
    }

    #[test]
    fn verify_errors_in_go_order() {
        use SmuxConfigError as E;
        let cases: &[(i64, i64, i64, i64, i64, E)] = &[
            (0, 4194304, 2097152, 8192, 10, E::UnsupportedProtocolVersion),
            (3, 4194304, 2097152, 8192, 10, E::UnsupportedProtocolVersion),
            (
                2,
                4194304,
                2097152,
                8192,
                0,
                E::KeepAliveIntervalNotPositive,
            ),
            // Deviation V12: Go accepts a negative interval here and panics in time.NewTicker
            // when the first session starts; the clamp turns it into this startup error.
            (
                2,
                4194304,
                2097152,
                8192,
                -1,
                E::KeepAliveIntervalNotPositive,
            ),
            (2, 4194304, 2097152, 8192, 31, E::KeepAliveTimeoutTooSmall),
            (2, 4194304, 2097152, 0, 10, E::MaxFrameSizeNotPositive),
            (2, 4194304, 2097152, 65536, 10, E::MaxFrameSizeTooLarge),
            (2, 0, 2097152, 8192, 10, E::MaxReceiveBufferNotPositive),
            (
                2,
                2147483648,
                2097152,
                8192,
                10,
                E::MaxReceiveBufferTooLarge,
            ),
            (2, 4194304, 0, 8192, 10, E::MaxStreamBufferNotPositive),
            (
                2,
                4194304,
                8388608,
                8192,
                10,
                E::MaxStreamBufferLargerThanReceiveBuffer,
            ),
        ];
        for &(ver, rbuf, sbuf, frame, keep, want) in cases {
            assert_eq!(
                build_smux_config(ver, rbuf, sbuf, frame, keep),
                Err(want),
                "({ver}, {rbuf}, {sbuf}, {frame}, {keep})"
            );
        }
    }

    #[test]
    fn keepalive_30_is_exactly_the_timeout() {
        // KeepAliveTimeout == KeepAliveInterval is accepted (the check is `<`).
        assert!(build_smux_config(2, 4194304, 2097152, 8192, 30).is_ok());
    }
}
