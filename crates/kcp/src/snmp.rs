//! Global KCP statistics (port of kcp-go `snmp.go`).
//!
//! [`DEFAULT_SNMP`] is the process-wide collector, like Go's `DefaultSnmp`. Its fields are
//! `AtomicU64` counters in **exactly Go's struct field order**, so that the `Display` of a
//! snapshot matches Go's `fmt.Sprintf("%+v", DefaultSnmp.Copy())` (kcptun logs it on SIGUSR1).
//! Note the two places where Go's other views differ from the struct:
//! - [`Snmp::header`] says `FECFullShards` for the `FECFullShardSet` field;
//! - [`Snmp::header`] and [`Snmp::to_slice`] list `FECParityShards, FECErrs, FECRecovered`,
//!   while the struct (and `%+v`) order is `FECRecovered, FECErrs, FECParityShards`.
//!
//! Counters are updated with relaxed atomics: they are statistics, never used to synchronise.
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Defines `Snmp` (atomic counters) and `SnmpSnapshot` (plain values) with the same fields,
/// plus the Go field names in struct order.
macro_rules! snmp_fields {
    ($($(#[doc = $doc:literal])* $field:ident => $go:literal,)*) => {
        /// Network statistics counters.
        // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp
        #[derive(Debug, Default)]
        pub struct Snmp {
            $($(#[doc = $doc])* pub $field: AtomicU64,)*
        }

        /// A point-in-time copy of [`Snmp`] (Go's `Copy()` returns a new `*Snmp`).
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct SnmpSnapshot {
            $($(#[doc = $doc])* pub $field: u64,)*
        }

        impl Snmp {
            /// A collector with every counter at 0.
            // Go: kcp-go/v5@v5.6.66 snmp.go:newSnmp()
            pub const fn new() -> Self {
                Snmp { $($field: AtomicU64::new(0),)* }
            }

            /// Loads every counter.
            // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp.Copy()
            pub fn copy(&self) -> SnmpSnapshot {
                SnmpSnapshot { $($field: self.$field.load(Ordering::Relaxed),)* }
            }

            /// Sets every counter to 0.
            // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp.Reset()
            pub fn reset(&self) {
                $(self.$field.store(0, Ordering::Relaxed);)*
            }
        }

        impl SnmpSnapshot {
            /// Go's struct field names, in declaration order (the `%+v` order).
            pub const FIELD_NAMES: [&'static str; SNMP_FIELDS] = [$($go,)*];

            /// The values in struct field order.
            pub fn values(&self) -> [u64; SNMP_FIELDS] {
                [$(self.$field,)*]
            }
        }
    };
}

/// Number of counters in [`Snmp`].
pub const SNMP_FIELDS: usize = 30;

snmp_fields! {
    /// Bytes sent from the upper level.
    bytes_sent => "BytesSent",
    /// Bytes received to the upper level.
    bytes_received => "BytesReceived",
    /// Maximum number of connections ever reached.
    max_conn => "MaxConn",
    /// Accumulated active open connections.
    active_opens => "ActiveOpens",
    /// Accumulated passive open connections.
    passive_opens => "PassiveOpens",
    /// Current number of established connections.
    curr_estab => "CurrEstab",
    /// UDP read errors reported from the socket.
    in_errs => "InErrs",
    /// CRC32 checksum errors (and AEAD open failures).
    in_csum_errors => "InCsumErrors",
    /// Packet input errors reported from KCP.
    kcp_in_errors => "KCPInErrors",
    /// Incoming packets.
    in_pkts => "InPkts",
    /// Outgoing packets.
    out_pkts => "OutPkts",
    /// Incoming KCP segments.
    in_segs => "InSegs",
    /// Outgoing KCP segments.
    out_segs => "OutSegs",
    /// UDP bytes received.
    in_bytes => "InBytes",
    /// UDP bytes sent.
    out_bytes => "OutBytes",
    /// Accumulated retransmitted segments.
    retrans_segs => "RetransSegs",
    /// Accumulated fast-retransmitted segments.
    fast_retrans_segs => "FastRetransSegs",
    /// Accumulated early-retransmitted segments.
    early_retrans_segs => "EarlyRetransSegs",
    /// Segments inferred as lost.
    lost_segs => "LostSegs",
    /// Duplicated segments.
    repeat_segs => "RepeatSegs",
    /// FEC segments that are full.
    fec_full_shard_set => "FECFullShardSet",
    /// Correct packets recovered by FEC.
    fec_recovered => "FECRecovered",
    /// Incorrect packets recovered by FEC.
    fec_errs => "FECErrs",
    /// FEC segments received.
    fec_parity_shards => "FECParityShards",
    /// Parity shards not yet received.
    fec_shard_set => "FECShardSet",
    /// Minimum id of FEC shards.
    fec_shard_min => "FECShardMin",
    /// Length of the send queue ring buffer (gauge).
    ring_buffer_snd_queue => "RingBufferSndQueue",
    /// Length of the receive queue ring buffer (gauge).
    ring_buffer_rcv_queue => "RingBufferRcvQueue",
    /// Length of the send buffer ring buffer (gauge).
    ring_buffer_snd_buffer => "RingBufferSndBuffer",
    /// OOB packets received.
    oob_packets => "OOBPackets",
}

/// The global statistics collector.
// Go: kcp-go/v5@v5.6.66 snmp.go:DefaultSnmp
pub static DEFAULT_SNMP: Snmp = Snmp::new();

/// Go's `Header()` names (note `FECFullShards` and the FEC order).
// Go: kcp-go/v5@v5.6.66 snmp.go:Snmp.Header()
const HEADER: [&str; SNMP_FIELDS] = [
    "BytesSent",
    "BytesReceived",
    "MaxConn",
    "ActiveOpens",
    "PassiveOpens",
    "CurrEstab",
    "InErrs",
    "InCsumErrors",
    "KCPInErrors",
    "InPkts",
    "OutPkts",
    "InSegs",
    "OutSegs",
    "InBytes",
    "OutBytes",
    "RetransSegs",
    "FastRetransSegs",
    "EarlyRetransSegs",
    "LostSegs",
    "RepeatSegs",
    "FECFullShards",
    "FECParityShards",
    "FECErrs",
    "FECRecovered",
    "FECShardSet",
    "FECShardMin",
    "RingBufferSndQueue",
    "RingBufferRcvQueue",
    "RingBufferSndBuffer",
    "OOBPackets",
];

impl Snmp {
    /// All field names, as Go's `Header()` returns them (the CSV header of `-snmplog`).
    // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp.Header()
    pub fn header(&self) -> Vec<String> {
        HEADER.iter().map(|s| (*s).to_string()).collect()
    }

    /// The current values as decimal strings, in [`header`](Self::header) order.
    // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp.ToSlice()
    pub fn to_slice(&self) -> Vec<String> {
        self.copy().to_slice()
    }
}

impl SnmpSnapshot {
    /// The values as decimal strings, in Go's `Header()`/`ToSlice()` order.
    // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp.ToSlice()
    pub fn to_slice(&self) -> Vec<String> {
        [
            self.bytes_sent,
            self.bytes_received,
            self.max_conn,
            self.active_opens,
            self.passive_opens,
            self.curr_estab,
            self.in_errs,
            self.in_csum_errors,
            self.kcp_in_errors,
            self.in_pkts,
            self.out_pkts,
            self.in_segs,
            self.out_segs,
            self.in_bytes,
            self.out_bytes,
            self.retrans_segs,
            self.fast_retrans_segs,
            self.early_retrans_segs,
            self.lost_segs,
            self.repeat_segs,
            self.fec_full_shard_set,
            self.fec_parity_shards,
            self.fec_errs,
            self.fec_recovered,
            self.fec_shard_set,
            self.fec_shard_min,
            self.ring_buffer_snd_queue,
            self.ring_buffer_rcv_queue,
            self.ring_buffer_snd_buffer,
            self.oob_packets,
        ]
        .iter()
        .map(u64::to_string)
        .collect()
    }
}

/// Go's `%+v` of the `*Snmp` that `Copy()` returns: `&{BytesSent:0 BytesReceived:0 ...}` with
/// the fields in struct order.
impl fmt::Display for SnmpSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("&{")?;
        for (i, (name, value)) in Self::FIELD_NAMES.iter().zip(self.values()).enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{name}:{value}")?;
        }
        f.write_str("}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::vectors;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct SnmpCase {
        name: String,
        fields: Vec<String>,
        values: Vec<u64>,
        header: Vec<String>,
        to_slice: Vec<String>,
        format: String,
    }

    /// Fills a fresh collector with `values` in struct field order, through the atomics.
    fn filled(values: &[u64]) -> Snmp {
        let s = Snmp::new();
        let counters = [
            &s.bytes_sent,
            &s.bytes_received,
            &s.max_conn,
            &s.active_opens,
            &s.passive_opens,
            &s.curr_estab,
            &s.in_errs,
            &s.in_csum_errors,
            &s.kcp_in_errors,
            &s.in_pkts,
            &s.out_pkts,
            &s.in_segs,
            &s.out_segs,
            &s.in_bytes,
            &s.out_bytes,
            &s.retrans_segs,
            &s.fast_retrans_segs,
            &s.early_retrans_segs,
            &s.lost_segs,
            &s.repeat_segs,
            &s.fec_full_shard_set,
            &s.fec_recovered,
            &s.fec_errs,
            &s.fec_parity_shards,
            &s.fec_shard_set,
            &s.fec_shard_min,
            &s.ring_buffer_snd_queue,
            &s.ring_buffer_rcv_queue,
            &s.ring_buffer_snd_buffer,
            &s.oob_packets,
        ];
        assert_eq!(counters.len(), values.len());
        for (c, v) in counters.iter().zip(values) {
            c.store(*v, Ordering::Relaxed);
        }
        s
    }

    #[test]
    fn vectors_kcp_snmp() {
        let file = vectors!("kcp");
        let mut n = 0;
        for case in file.cases_with_prefix("snmp/") {
            let c: SnmpCase = case.to();
            assert_eq!(c.fields, SnmpSnapshot::FIELD_NAMES, "case {}", c.name);
            let s = filled(&c.values);
            let snap = s.copy();
            assert_eq!(snap.values().to_vec(), c.values, "case {}", c.name);
            assert_eq!(s.header(), c.header, "case {}", c.name);
            assert_eq!(s.to_slice(), c.to_slice, "case {}", c.name);
            assert_eq!(snap.to_string(), c.format, "case {}", c.name);
            s.reset();
            assert_eq!(s.copy(), SnmpSnapshot::default(), "case {}", c.name);
            n += 1;
        }
        assert_eq!(n, 3);
    }

    #[test]
    fn default_snmp_is_shared_and_counts() {
        let before = DEFAULT_SNMP.oob_packets.load(Ordering::Relaxed);
        DEFAULT_SNMP.oob_packets.fetch_add(2, Ordering::Relaxed);
        assert!(DEFAULT_SNMP.copy().oob_packets >= before + 2);
        assert_eq!(DEFAULT_SNMP.header().len(), SNMP_FIELDS);
        assert_eq!(DEFAULT_SNMP.to_slice().len(), SNMP_FIELDS);
    }

    #[test]
    fn zero_snapshot_display() {
        let s = SnmpSnapshot::default().to_string();
        assert!(
            s.starts_with("&{BytesSent:0 BytesReceived:0 MaxConn:0 "),
            "{s}"
        );
        assert!(s.ends_with(" OOBPackets:0}"), "{s}");
    }
}
