package main

// Area "timefmt" (plan step 08.4): Go's reference-layout time formatting, time.Time.Format
// (Go standard library time/format.go: nextStdChunk, appendFormat, appendInt, appendNano).
//
// kcptun feeds a user-supplied layout to Format in exactly one place: std/snmp.go:56 builds
// the SNMP log file name with `logdir + time.Now().Format(logfile)`, so any layout a user can
// write into -snmplog has to render the way Go renders it. The cases below cover every
// reference-layout token Go knows (not only the ones -snmplog is likely to use), the layout
// constants of the time package, kcptun-shaped file names, and the quirks of the layout
// scanner - "Month" and "Janx" are literals, "_2006" is an underscore plus a year, ".0001" is
// not a fraction at all but the literal ".00" followed by a zero-padded month, and
// "snmp-pm.log" quietly turns into "snmp-am.log" before noon.
//
// Each case records the instant as (unix seconds, nanoseconds) plus the zone it is rendered
// in - the zone's abbreviation ("" for a zone without a name, where Go falls back to the
// numeric form for MST) and its offset east of UTC in seconds - so the Rust port formats from
// the same inputs. Cases are ordered instant-major, then zone, then layout.

import (
	"fmt"
	"time"
)

// timefmtCase is one time.Time.Format vector.
type timefmtCase struct {
	Name   string `json:"name"`
	Layout string `json:"layout"`
	// Unix and Nanos are the instant; Zone and Offset are the location it is rendered in.
	Unix   int64  `json:"unix"`
	Nanos  int    `json:"nanos"`
	Zone   string `json:"zone"`
	Offset int    `json:"offset"`
	Out    string `json:"out"`
}

func (c timefmtCase) CaseName() string { return c.Name }

// timefmtInstant is one instant of the table below, given by its UTC wall clock.
type timefmtInstant struct {
	id                            string
	year                          int
	month                         time.Month
	day, hour, minute, second, ns int
	what                          string // what this instant is for (documentation only)
}

// timefmtInstants are the instants the layouts are rendered at.
var timefmtInstants = []timefmtInstant{
	{"t0", 2026, time.September, 22, 15, 4, 5, 123456789, "afternoon, two digits everywhere"},
	{"t1", 2006, time.January, 2, 3, 4, 5, 0, "Go's own reference time: single digits, AM"},
	{"t2", 2026, time.January, 1, 0, 0, 0, 0, "midnight is 12AM; year day 1"},
	{"t3", 2024, time.February, 29, 12, 0, 0, 120000000, "noon is 12PM; leap day; .999 trims"},
	{"t4", 2026, time.December, 31, 23, 59, 59, 999999999, "last second of the year"},
	{"t5", 6, time.March, 5, 7, 8, 9, 0, "year 6: \"2006\" pads to 0006"},
}

// timefmtZone is one location of the table below.
type timefmtZone struct {
	id  string
	loc *time.Location
}

// timefmtZones are the locations the instants are rendered in. Fixed zones keep the vectors
// independent of the tzdata on the generating machine.
var timefmtZones = []timefmtZone{
	{"utc", time.UTC},                            // named, offset 0: "Z" for the Z-layouts
	{"mst", time.FixedZone("MST", -7*3600)},      // named, negative
	{"noname", time.FixedZone("", 5*3600+30*60)}, // unnamed: MST falls back to "+0530"
	{"lmt", time.FixedZone("LMT", 3781)},         // +01:03:01, an offset with seconds
}

// timefmtLayouts are all the layouts, rendered at t0 in the named zones.
var timefmtLayouts = []string{
	// One reference-layout token at a time, in the order of time/format.go's std constants.
	"January", "Jan", "1", "01",
	"Monday", "Mon",
	"2", "_2", "02",
	"__2", "002",
	"15", "3", "03", "4", "04", "5", "05",
	"2006", "06",
	"PM", "pm",
	"MST",
	"Z0700", "Z070000", "Z07", "Z07:00", "Z07:00:00",
	"-0700", "-070000", "-07", "-07:00", "-07:00:00",
	".0", ".00", ".000", ".000000", ".000000000",
	".9", ".99", ".999", ".999999999",
	",000", ",999",
	// Quirks of the scanner.
	"Month",    // "Mon" followed by a lower-case letter: a literal
	"Janx",     // ditto for "Jan"
	"Januaryx", // "January" wins before the lower-case test is reached
	"Mo", "Ja", // too short to be a token
	"_2006",        // a literal underscore followed by the long year
	"__3",          // not the year day; "3" is the 12-hour clock
	".0001",        // a digit after the zeros: not a fraction, but ".00" plus "01" (the month)
	".00000000000", // 11 digits: still one fraction, capped by appendNano at 9
	"MSTMST", "PMpm", "15150404",
	"1 2 3 4 5", "020106", "20060102150405",
	"Z", "T", "--0700", "0", "7", "8", "9", "",
	// The layout constants of the time package.
	"01/02 03:04:05PM '06 -0700",
	"Mon Jan _2 15:04:05 2006",
	"Mon Jan _2 15:04:05 MST 2006",
	"Mon Jan 02 15:04:05 -0700 2006",
	"02 Jan 06 15:04 MST",
	"02 Jan 06 15:04 -0700",
	"Monday, 02-Jan-06 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 -0700",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
	"3:04PM",
	"Jan _2 15:04:05",
	"Jan _2 15:04:05.000",
	"Jan _2 15:04:05.000000",
	"Jan _2 15:04:05.000000000",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"15:04:05",
	// What kcptun itself renders: the Go log header and -snmplog file names.
	"2006/01/02 15:04:05",
	"kcptun-snmp-20060102.log",
	"snmp-2006-01-02T15-04-05.csv",
	"/var/log/kcptun/2006/01/02/snmp.log",
	"snmp.log",
	"snmp-pm.log", // the "pm" in the name is a token: "snmp-am.log" before noon
}

// timefmtZoneLayouts are rendered at t0 in the zones that are not in timefmtLayouts' sweep:
// everything whose output depends on the zone's name or offset.
var timefmtZoneLayouts = []string{
	"MST",
	"Z0700", "Z070000", "Z07", "Z07:00", "Z07:00:00",
	"-0700", "-070000", "-07", "-07:00", "-07:00:00",
	"2006-01-02T15:04:05Z07:00",
	"Mon Jan _2 15:04:05 MST 2006",
	"Mon, 02 Jan 2006 15:04:05 -0700",
}

// timefmtDateLayouts are rendered at every other instant: everything whose output depends on
// the calendar or the clock.
var timefmtDateLayouts = []string{
	"2006-01-02T15:04:05.999999999Z07:00",
	"Monday, 02-Jan-06 15:04:05 MST",
	"January 2, 2006",
	"1 2 3 4 5",
	"_2", "__2", "002",
	"03:04:05PM", "3:04pm", "15:04:05",
	".000", ".999", ".000000000",
	"kcptun-snmp-20060102.log",
}

// genTimefmt renders every layout at the instants and zones of the tables above.
func genTimefmt() ([]any, error) {
	var cases []any
	add := func(inst timefmtInstant, z timefmtZone, layouts []string) {
		utc := time.Date(inst.year, inst.month, inst.day, inst.hour, inst.minute, inst.second,
			inst.ns, time.UTC)
		t := utc.In(z.loc)
		name, offset := t.Zone()
		for _, layout := range layouts {
			cases = append(cases, timefmtCase{
				Name:   fmt.Sprintf("%s/%s/%s", inst.id, z.id, layout),
				Layout: layout,
				Unix:   t.Unix(),
				Nanos:  t.Nanosecond(),
				Zone:   name,
				Offset: offset,
				Out:    t.Format(layout),
			})
		}
	}

	t0 := timefmtInstants[0]
	// Every layout in the two named zones, then the zone-dependent ones in the other two.
	add(t0, timefmtZones[0], timefmtLayouts)
	add(t0, timefmtZones[1], timefmtLayouts)
	add(t0, timefmtZones[2], timefmtZoneLayouts)
	add(t0, timefmtZones[3], timefmtZoneLayouts)
	// The remaining instants, in the zone with the most interesting offset.
	for _, inst := range timefmtInstants[1:] {
		add(inst, timefmtZones[1], timefmtDateLayouts)
	}
	return cases, nil
}
