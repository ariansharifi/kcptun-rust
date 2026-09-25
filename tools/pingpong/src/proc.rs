//! Parsers for the `/proc` files `labsample` reads.
//!
//! Split out from the binary so that they are unit-tested on any platform: the sampler only
//! runs on the lab host (Linux), but a wrong field index in `/proc/<pid>/stat` would silently
//! ruin a six-hour soak, and that is not something to discover on the host.
//!
//! References: `proc_pid_stat(5)` and `proc_pid_status(5)` (Linux 6.17).

/// The fields of `/proc/<pid>/stat` the lab cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stat {
    /// Process state (`R`, `S`, `D`, `Z`, …).
    pub state: char,
    /// Minor faults.
    pub minflt: u64,
    /// Major faults.
    pub majflt: u64,
    /// User CPU time, in clock ticks.
    pub utime: u64,
    /// System CPU time, in clock ticks.
    pub stime: u64,
    /// Threads in the process.
    pub num_threads: u64,
    /// Start time after boot, in clock ticks. Together with the pid it identifies the process.
    pub starttime: u64,
}

impl Stat {
    /// User plus system time, in clock ticks.
    pub fn cpu_ticks(&self) -> u64 {
        self.utime.saturating_add(self.stime)
    }
}

/// Parses `/proc/<pid>/stat`.
///
/// The second field is the executable name in parentheses and may itself contain spaces and
/// parentheses (`kr-client` cannot, but a renamed thread can), so the fields are counted from
/// the **last** `)`, exactly as `proc_pid_stat(5)` prescribes.
pub fn parse_stat(text: &str) -> Option<Stat> {
    let close = text.rfind(')')?;
    let rest = text.get(close + 1..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // `fields[0]` is field 3 (state), so field N is `fields[N - 3]`.
    let at = |n: usize| -> Option<u64> { fields.get(n - 3)?.parse().ok() };
    Some(Stat {
        state: fields.first()?.chars().next()?,
        minflt: at(10)?,
        majflt: at(12)?,
        utime: at(14)?,
        stime: at(15)?,
        num_threads: at(20)?,
        starttime: at(22)?,
    })
}

/// The memory and scheduling fields of `/proc/<pid>/status`, in kB and counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {
    /// `VmRSS`: resident set size.
    pub vm_rss_kb: u64,
    /// `VmHWM`: the peak resident set size, which never falls.
    pub vm_hwm_kb: u64,
    /// `RssAnon`: heap and stacks.
    pub rss_anon_kb: u64,
    /// `RssFile`: file-backed pages, mostly the binary's own text.
    pub rss_file_kb: u64,
    /// `VmSize`: address space.
    pub vm_size_kb: u64,
    /// `Threads`.
    pub threads: u64,
    /// `voluntary_ctxt_switches`.
    pub voluntary_ctxt_switches: u64,
    /// `nonvoluntary_ctxt_switches`.
    pub nonvoluntary_ctxt_switches: u64,
}

/// Parses `/proc/<pid>/status`. Missing keys stay zero (they differ between kernels).
pub fn parse_status(text: &str) -> Status {
    let mut out = Status::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        // "VmRSS:\t    2416 kB" — the number is the first whitespace-separated token.
        let Some(number) = value.split_whitespace().next() else {
            continue;
        };
        let Ok(n) = number.parse::<u64>() else {
            continue;
        };
        match key {
            "VmRSS" => out.vm_rss_kb = n,
            "VmHWM" => out.vm_hwm_kb = n,
            "RssAnon" => out.rss_anon_kb = n,
            "RssFile" => out.rss_file_kb = n,
            "VmSize" => out.vm_size_kb = n,
            "Threads" => out.threads = n,
            "voluntary_ctxt_switches" => out.voluntary_ctxt_switches = n,
            "nonvoluntary_ctxt_switches" => out.nonvoluntary_ctxt_switches = n,
            _ => {}
        }
    }
    out
}

/// Parses the three load averages out of `/proc/loadavg`.
pub fn parse_loadavg(text: &str) -> Option<(f64, f64, f64)> {
    let mut it = text.split_whitespace();
    let one = it.next()?.parse().ok()?;
    let five = it.next()?.parse().ok()?;
    let fifteen = it.next()?.parse().ok()?;
    Some((one, five, fifteen))
}

/// One row of an SNMP CSV written by `-snmplog`, reduced to the counters a report quotes.
///
/// Both implementations write the same header (`Unix` then `kcp-go`'s 30 counter names), so the
/// column is found by name rather than by position.
pub fn snmp_column(header: &str, row: &str, name: &str) -> Option<u64> {
    let index = header.split(',').position(|h| h.trim() == name)?;
    row.split(',').nth(index)?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/proc/<pid>/stat` line from lab-arm64 (Linux 6.17, aarch64), with the pid and the
    /// name replaced. The comm deliberately contains a space and a `)` to pin the parsing rule.
    const STAT: &str = "1234 (kr client) S 1 1234 1234 0 -1 4194560 1817 0 0 0 \
        731 218 0 0 20 0 9 0 5573182 421138432 1370 18446744073709551615 \
        1 1 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0";

    const STATUS: &str = "Name:\tkr-client\nUmask:\t0022\nState:\tS (sleeping)\n\
        Tgid:\t1234\nPid:\t1234\nVmSize:\t  411268 kB\nVmRSS:\t    5480 kB\n\
        RssAnon:\t    3064 kB\nRssFile:\t    2416 kB\nRssShmem:\t       0 kB\n\
        VmHWM:\t   12880 kB\nThreads:\t9\nvoluntary_ctxt_switches:\t1477\n\
        nonvoluntary_ctxt_switches:\t23\n";

    #[test]
    fn stat_fields_are_counted_from_the_last_parenthesis() {
        let s = parse_stat(STAT).expect("parses");
        assert_eq!(s.state, 'S');
        assert_eq!(s.minflt, 1817);
        assert_eq!(s.majflt, 0);
        assert_eq!(s.utime, 731);
        assert_eq!(s.stime, 218);
        assert_eq!(s.num_threads, 9);
        assert_eq!(s.starttime, 5573182);
        assert_eq!(s.cpu_ticks(), 949);
    }

    #[test]
    fn a_truncated_or_empty_stat_is_none_not_a_panic() {
        assert_eq!(parse_stat(""), None);
        assert_eq!(parse_stat("1234 (kr-client) S 1 2 3"), None);
        assert_eq!(parse_stat("no parenthesis here"), None);
    }

    #[test]
    fn status_reads_the_memory_and_switch_counters() {
        let s = parse_status(STATUS);
        assert_eq!(s.vm_rss_kb, 5480);
        assert_eq!(s.vm_hwm_kb, 12880);
        assert_eq!(s.rss_anon_kb, 3064);
        assert_eq!(s.rss_file_kb, 2416);
        assert_eq!(s.vm_size_kb, 411268);
        assert_eq!(s.threads, 9);
        assert_eq!(s.voluntary_ctxt_switches, 1477);
        assert_eq!(s.nonvoluntary_ctxt_switches, 23);
    }

    #[test]
    fn an_unknown_status_shape_yields_zeroes_rather_than_failing() {
        assert_eq!(
            parse_status("garbage\nVmRSS: not-a-number\n"),
            Status::default()
        );
    }

    #[test]
    fn loadavg_is_read_from_the_first_three_columns() {
        assert_eq!(
            parse_loadavg("0.31 0.42 0.55 2/812 4242\n"),
            Some((0.31, 0.42, 0.55))
        );
        assert_eq!(parse_loadavg(""), None);
    }

    #[test]
    fn snmp_columns_are_found_by_name() {
        let header = "Unix,BytesSent,BytesReceived,MaxConn,ActiveOpens,PassiveOpens,CurrEstab";
        let row = "1758614400,1024,2048,4,4,0,3";
        assert_eq!(snmp_column(header, row, "CurrEstab"), Some(3));
        assert_eq!(snmp_column(header, row, "BytesSent"), Some(1024));
        assert_eq!(snmp_column(header, row, "Nonesuch"), None);
    }
}
