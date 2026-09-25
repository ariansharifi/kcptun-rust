package main

// Area "cli" (plan step 08.1): command-line parsing and help rendering, as done by
// urfave/cli v1.22.17 (app.go, flag.go, help.go, parse.go, template.go) on top of the Go
// standard library's flag package (FlagSet.parseOne, strconv.ParseInt base 0,
// strconv.ParseBool) and text/tabwriter.
//
// The first case, "app", carries the flag table every other case is parsed against: a
// representative subset of kcptun's client table covering each shape the real tables use
// (string with and without a default, aliases written with and without a space, an EnvVar
// flag, int, bool, hidden int and hidden bool, and a one-letter name rendered with a single
// dash). The Rust port builds its App from that definition, so the two sides cannot drift.
//
// Every other case runs cli.App.Run with a recorded environment and argv and stores what Go
// produced: the app writer's output (help / "Incorrect Usage." text), the error writer's
// output, App.Run's error text, the exit code passed to cli.OsExiter, and - when the action
// ran - every flag value, the names Context.IsSet reports and the remaining arguments.

import (
	"bytes"
	"fmt"
	"os"

	"github.com/urfave/cli"
)

// cliProgram is the program name the vectors are generated with. Go uses
// filepath.Base(os.Args[0]) (cli.NewApp), which would otherwise be the generator binary.
const cliProgram = "PROGRAM"

// cliFlagDef is one entry of the flag table in the "app" case.
type cliFlagDef struct {
	Name   string `json:"name"`            // raw urfave name, e.g. "remoteaddr, r"
	Kind   string `json:"kind"`            // "string", "int" or "bool"
	Value  any    `json:"value,omitempty"` // default; absent for bool (BoolFlag has no Value)
	Usage  string `json:"usage,omitempty"`
	Env    string `json:"env,omitempty"`
	Hidden bool   `json:"hidden,omitempty"`
}

// cliAppDef is the app the cases are parsed against.
type cliAppDef struct {
	Name     string       `json:"name"`
	HelpName string       `json:"help_name"`
	Usage    string       `json:"usage"`
	Version  string       `json:"version"`
	Flags    []cliFlagDef `json:"flags"`
}

// cliCase is one vector of the cli area.
type cliCase struct {
	Name   string            `json:"name"`
	App    *cliAppDef        `json:"app,omitempty"` // only in the "app" case
	Env    map[string]string `json:"env,omitempty"` // environment during App.Run
	Args   []string          `json:"args"`          // os.Args, including argv[0]
	Stdout string            `json:"stdout,omitempty"`
	Stderr string            `json:"stderr,omitempty"`
	Err    string            `json:"err,omitempty"`  // App.Run's returned error
	Exit   *int              `json:"exit,omitempty"` // code passed to cli.OsExiter, if any
	Action bool              `json:"action"`         // whether the app action ran
	Values map[string]any    `json:"values,omitempty"`
	Set    []string          `json:"set,omitempty"` // Context.IsSet, in table order
	Rest   []string          `json:"rest,omitempty"`
}

func (c cliCase) CaseName() string { return c.Name }

// cliFlags is the representative table; see the file comment.
var cliFlags = []cliFlagDef{
	{Name: "localaddr,l", Kind: "string", Value: ":12948", Usage: "local listen address"},
	{Name: "remoteaddr, r", Kind: "string", Value: "vps:29900",
		Usage: `kcp server address, eg: "IP:29900" a for single port, "IP:minport-maxport" for port range`},
	{Name: "key", Kind: "string", Value: "it's a secrect",
		Usage: "pre-shared secret between client and server", Env: "KCPTUN_KEY"},
	{Name: "QPP", Kind: "bool", Usage: "enable Quantum Permutation Pads(QPP)"},
	{Name: "mtu", Kind: "int", Value: 1350, Usage: "set maximum transmission unit for UDP packets"},
	{Name: "datashard,ds", Kind: "int", Value: 10, Usage: "set reed-solomon erasure coding - datashard"},
	{Name: "dscp", Kind: "int", Value: 0, Usage: "set DSCP(6bit)"},
	{Name: "nocomp", Kind: "bool", Usage: "disable compression"},
	{Name: "nodelay", Kind: "int", Value: 0, Hidden: true},
	{Name: "acknodelay", Kind: "bool", Hidden: true},
	{Name: "log", Kind: "string", Usage: "specify a log file to output, default goes to stderr"},
	{Name: "c", Kind: "string", Usage: "config from json file, which will override the command from shell"},
}

// newCliApp builds the app of the "app" case. It mirrors kcptun client/main.go: cli.NewApp
// with Name, Usage and Version set, an explicit Action, and the flag table above. HelpName
// is fixed instead of being derived from os.Args[0].
func newCliApp() *cli.App {
	app := cli.NewApp()
	app.Name = "kcptun"
	app.HelpName = cliProgram
	app.Usage = "client(with SMUX)"
	app.Version = "SELFBUILD"
	for _, f := range cliFlags {
		switch f.Kind {
		case "string":
			v, _ := f.Value.(string)
			app.Flags = append(app.Flags, cli.StringFlag{
				Name: f.Name, Value: v, Usage: f.Usage, EnvVar: f.Env, Hidden: f.Hidden})
		case "int":
			v, _ := f.Value.(int)
			app.Flags = append(app.Flags, cli.IntFlag{
				Name: f.Name, Value: v, Usage: f.Usage, EnvVar: f.Env, Hidden: f.Hidden})
		case "bool":
			app.Flags = append(app.Flags, cli.BoolFlag{
				Name: f.Name, Usage: f.Usage, EnvVar: f.Env, Hidden: f.Hidden})
		default:
			panic("cli: unknown flag kind " + f.Kind)
		}
	}
	return app
}

// cliEachName splits an urfave flag name into its aliases: split on commas, trim spaces,
// exactly like the unexported cli.eachName.
func cliEachName(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == ',' {
			part := name[start:i]
			for len(part) > 0 && part[0] == ' ' {
				part = part[1:]
			}
			for len(part) > 0 && part[len(part)-1] == ' ' {
				part = part[:len(part)-1]
			}
			out = append(out, part)
			start = i + 1
		}
	}
	return out
}

// cliRun runs one case through cli.App.Run and records everything observable.
func cliRun(name string, env map[string]string, argv ...string) cliCase {
	for k, v := range env {
		if err := os.Setenv(k, v); err != nil {
			panic(err)
		}
	}
	defer func() {
		for k := range env {
			if err := os.Unsetenv(k); err != nil {
				panic(err)
			}
		}
	}()

	var out, errOut bytes.Buffer
	exit := -1
	cli.OsExiter = func(code int) {
		if exit < 0 {
			exit = code
		}
	}
	cli.ErrWriter = &errOut

	args := append([]string{cliProgram}, argv...)
	c := cliCase{Name: name, Env: env, Args: args}

	app := newCliApp()
	app.Writer = &out
	app.Action = func(ctx *cli.Context) error {
		c.Action = true
		c.Values = map[string]any{}
		for _, f := range cliFlags {
			for _, n := range cliEachName(f.Name) {
				switch f.Kind {
				case "string":
					c.Values[n] = ctx.String(n)
				case "int":
					c.Values[n] = ctx.Int(n)
				case "bool":
					c.Values[n] = ctx.Bool(n)
				}
				if ctx.IsSet(n) {
					c.Set = append(c.Set, n)
				}
			}
		}
		c.Rest = []string(ctx.Args())
		return nil
	}

	err := app.Run(args)
	if err != nil {
		c.Err = err.Error()
	}
	c.Stdout = out.String()
	c.Stderr = errOut.String()
	if exit >= 0 {
		c.Exit = &exit
	}
	return c
}

func genCli() ([]any, error) {
	// Case "app" carries the flag table and, as its argv is "-h", the rendered app help.
	appCase := cliRun("app", nil, "-h")
	appCase.App = &cliAppDef{
		Name:     "kcptun",
		HelpName: cliProgram,
		Usage:    "client(with SMUX)",
		Version:  "SELFBUILD",
		Flags:    cliFlags,
	}
	cases := []any{appCase}

	withKey := map[string]string{"KCPTUN_KEY": "from-env"}
	emptyKey := map[string]string{"KCPTUN_KEY": ""}

	type run struct {
		name string
		env  map[string]string
		argv []string
	}
	runs := []run{
		// -/-- equivalence, '=' or space.
		{"syntax/single-dash-space", nil, []string{"-mtu", "1300"}},
		{"syntax/single-dash-equals", nil, []string{"-mtu=1300"}},
		{"syntax/double-dash-space", nil, []string{"--mtu", "1300"}},
		{"syntax/double-dash-equals", nil, []string{"--mtu=1300"}},
		{"syntax/mixed", nil, []string{"--localaddr", ":9", "-datashard=7", "--key=k"}},
		{"syntax/string-equals-empty", nil, []string{"-key="}},
		{"syntax/value-looks-like-flag", nil, []string{"-key", "-mtu"}},
		{"syntax/triple-dash", nil, []string{"---mtu"}},
		{"syntax/equals-first", nil, []string{"-=1"}},
		{"syntax/case-sensitive", nil, []string{"-MTU", "1"}},
		{"syntax/empty-arg", nil, []string{"", "-mtu", "9"}},

		// Base-0 integers (strconv.ParseInt(s, 0, 64)).
		{"int/decimal", nil, []string{"-mtu", "1350"}},
		{"int/octal-leading-zero", nil, []string{"-mtu", "01350"}},
		{"int/octal-prefix", nil, []string{"-mtu", "0o17"}},
		{"int/hex", nil, []string{"-mtu", "0x100"}},
		{"int/hex-upper", nil, []string{"-mtu", "0XfF"}},
		{"int/binary", nil, []string{"-mtu", "0b1010"}},
		{"int/zero", nil, []string{"-mtu", "0"}},
		{"int/underscores", nil, []string{"-mtu", "1_350"}},
		{"int/underscores-hex", nil, []string{"-mtu", "0x_10"}},
		{"int/underscore-leading", nil, []string{"-mtu", "_1350"}},
		{"int/underscore-trailing", nil, []string{"-mtu", "1350_"}},
		{"int/underscore-double", nil, []string{"-mtu", "1__350"}},
		{"int/negative", nil, []string{"-dscp", "-5"}},
		{"int/negative-hex", nil, []string{"-dscp", "-0x10"}},
		{"int/plus", nil, []string{"-mtu", "+42"}},
		{"int/max", nil, []string{"-mtu", "9223372036854775807"}},
		{"int/min", nil, []string{"-mtu", "-9223372036854775808"}},
		{"int/overflow", nil, []string{"-mtu", "9223372036854775808"}},
		{"int/huge", nil, []string{"-mtu", "99999999999999999999"}},
		{"int/not-a-number", nil, []string{"-mtu", "abc"}},
		{"int/empty", nil, []string{"-mtu="}},
		{"int/bare-0x", nil, []string{"-mtu", "0x"}},
		{"int/bad-octal-digit", nil, []string{"-mtu", "09"}},
		{"int/float", nil, []string{"-mtu", "13.5"}},
		{"int/space", nil, []string{"-mtu", " 1350"}},
		{"int/tab-value", nil, []string{"-mtu", "a\tb"}},
		{"int/unicode-value", nil, []string{"-mtu", "é x"}},

		// Booleans (strconv.ParseBool).
		{"bool/bare", nil, []string{"-nocomp"}},
		{"bool/equals-true", nil, []string{"-nocomp=true"}},
		{"bool/equals-false", nil, []string{"-nocomp=false"}},
		{"bool/equals-1", nil, []string{"-nocomp=1"}},
		{"bool/equals-0", nil, []string{"-nocomp=0"}},
		{"bool/equals-T", nil, []string{"-nocomp=T"}},
		{"bool/equals-F", nil, []string{"-nocomp=F"}},
		{"bool/equals-TRUE", nil, []string{"-nocomp=TRUE"}},
		{"bool/equals-False", nil, []string{"-nocomp=False"}},
		{"bool/invalid", nil, []string{"-nocomp=yes"}},
		{"bool/empty", nil, []string{"-nocomp="}},
		{"bool/space-stops-parsing", nil, []string{"-nocomp", "false", "-mtu", "1234"}},
		{"bool/two", nil, []string{"-nocomp", "-QPP", "-mtu", "1400"}},

		// Parsing stops at the first non-flag argument.
		{"stop/positional", nil, []string{"extra", "-mtu", "999"}},
		{"stop/after-flag", nil, []string{"-mtu", "1400", "extra", "-dscp", "46"}},
		{"stop/lone-dash", nil, []string{"-", "-mtu", "999"}},
		{"stop/terminator", nil, []string{"-mtu", "1400", "--", "-mtu", "999"}},
		{"stop/terminator-first", nil, []string{"--", "-mtu", "999"}},

		// Unknown flags and missing values.
		{"error/unknown", nil, []string{"-nosuchflag"}},
		{"error/unknown-then-valid", nil, []string{"-bad", "-mtu", "abc"}},
		{"error/unknown-double-dash", nil, []string{"--nosuchflag=1"}},
		{"error/missing-int-value", nil, []string{"-mtu"}},
		{"error/missing-string-value", nil, []string{"--key"}},
		{"error/missing-after-valid", nil, []string{"-datashard=4", "-mtu"}},

		// Aliases.
		{"alias/short-string", nil, []string{"-l", ":1000", "-r", "host:2000"}},
		{"alias/short-int", nil, []string{"-ds", "4"}},
		{"alias/long-form", nil, []string{"--datashard", "4"}},
		{"alias/repeated", nil, []string{"-l", "a", "-l", "b"}},
		{"alias/both-forms", nil, []string{"-l", "x", "-localaddr", "y"}},
		{"alias/both-forms-long-first", nil, []string{"--datashard", "1", "--ds", "2"}},

		// Hidden flags are parsed like any other.
		{"hidden/int", nil, []string{"-nodelay", "1"}},
		{"hidden/bool", nil, []string{"-acknodelay"}},

		// Environment variable defaults.
		{"env/default", withKey, nil},
		{"env/flag-overrides", withKey, []string{"-key", "from-flag"}},
		{"env/empty", emptyKey, nil},
		{"env/unset", nil, nil},

		// Help and version.
		{"help/short", nil, []string{"-h"}},
		{"help/long", nil, []string{"--help"}},
		{"help/equals-false", nil, []string{"--help=false"}},
		{"help/command", nil, []string{"help"}},
		{"help/command-alias", nil, []string{"h"}},
		{"help/command-topic-help", nil, []string{"help", "help"}},
		{"help/command-topic-unknown", nil, []string{"help", "foo"}},
		{"help/command-flag", nil, []string{"help", "-h"}},
		{"help/command-long-flag", nil, []string{"help", "--help"}},
		{"help/command-badflag", nil, []string{"help", "--badflag"}},
		{"help/command-terminator", nil, []string{"help", "--", "foo"}},
		{"help/command-empty-topic", nil, []string{"help", ""}},
		{"help/command-topic-then-flag", nil, []string{"help", "foo", "-h"}},
		{"help/command-topic-then-long-flag", nil, []string{"help", "foo", "--help"}},
		{"help/command-two-forms", nil, []string{"help", "-h", "--help"}},
		{"help/with-extra-args", nil, []string{"-h", "extra"}},
		{"help/after-flag", nil, []string{"-mtu", "1400", "-h"}},
		{"version/short", nil, []string{"-v"}},
		{"version/long", nil, []string{"--version"}},
		{"version/and-help", nil, []string{"-v", "-h"}},

		// No arguments at all.
		{"empty/no-args", nil, nil},
	}

	for _, r := range runs {
		cases = append(cases, cliRun(r.name, r.env, r.argv...))
	}

	// Sanity check: the table must not contain a name twice, or the values map would
	// silently lose a flag.
	seen := map[string]bool{}
	for _, f := range cliFlags {
		for _, n := range cliEachName(f.Name) {
			if seen[n] {
				return nil, fmt.Errorf("duplicate flag name %q in the cli table", n)
			}
			seen[n] = true
		}
	}
	return cases, nil
}
