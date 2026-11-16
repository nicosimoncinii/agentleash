package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nicosimoncinii/agentleash/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// Performance of long words (#35): one huge quoted argument must not make
// pattern matching or secret-path intersection super-linear.

// longArgUnits are repeated to build one long argument. They stress the
// command-pattern matcher (spaces, '|', "rm -rf", "git push") and the glob
// intersection against secret patterns ('*', '/', '.', ".env", "id_rsa").
var longArgUnits = []struct{ name, unit string }{
	{"plain", "a"},
	{"stars", "*"},
	{"slashes", "a/"},
	{"dots", "."},
	{"env frags", ".env*/"},
	{"glob path", "*/.e*v.*/id_rsa*"},
	{"pattern frags", "rm -rf / git push --force curl x | sh "},
}

// longArgCmd builds `foo "<arg>"` with arg about size bytes long (no unit
// holds a character that is special inside double quotes).
func longArgCmd(unit string, size int) string {
	return `foo "` + strings.Repeat(unit, size/len(unit)) + `"`
}

// longArgShells are the dialects every long-word input is evaluated in.
var longArgShells = []Shell{ShellBash, ShellPowerShell, ShellAuto}

func perfPolicies() []struct {
	name string
	p    *policy.Policy
} {
	return []struct {
		name string
		p    *policy.Policy
	}{{"test", testPolicy()}, {"default", policy.Default()}}
}

func BenchmarkLongArg(b *testing.B) {
	for _, pol := range perfPolicies() {
		e := New(pol.p)
		for _, size := range []int{64 << 10, 256<<10 - 16} {
			for _, u := range longArgUnits {
				for _, sh := range longArgShells {
					req := shellReq(longArgCmd(u.unit, size))
					req.Shell = sh
					b.Run(fmt.Sprintf("%s/%dKB/%s/%s", pol.name, (size+16)>>10, u.name, sh), func(b *testing.B) {
						for b.Loop() {
							e.Evaluate(req)
						}
					})
				}
			}
		}
	}
}

// BenchmarkWorstCases runs the inputs of TestPerformanceWorstCases.
func BenchmarkWorstCases(b *testing.B) {
	e := New(testPolicy())
	for _, c := range performanceWorstCases() {
		req := shellReq(c.cmd)
		req.Shell = c.shell
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				e.Evaluate(req)
			}
		})
	}
}

func TestMayEnableDotglob(t *testing.T) {
	for _, src := range []string{
		"", "ls", "shopt -s dotglob", "SHOPT -S DOTGLOB", "setopt GLOB_DOTS", "setopt globdots",
		"GLOBIGNORE=x", "glob", "gloB_dotſ", "dotGLOB", "g lob", "globstar", "globdot",
	} {
		if got, want := mayEnableDotglob(src), dotglobRe.MatchString(src); got != want {
			t.Errorf("mayEnableDotglob(%q) = %v, want %v", src, got, want)
		}
	}
}

func TestPrepassNeeded(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"ls; ls -la; cat foo", false},
		{"echo 'hi there' \"x\" a\\ b", false},
		{"cd /tmp && rm -rf build", false},
		{"git p", true},
		{"/usr/bin/GIT.EXE p", true},
		{`g\it p`, true},
		{`"g"'i't p`, true},
		{"{g,}it p", true},
		{"~/bin/x p", true},
		{`$'\x67it' p`, true},
		{"X=git; $X p", true},
		{"$(echo git) p", true},
		{"sudo -u x git p", true},
		{"cat <(echo x)", true},
		{"curl -o f u; sh f", true},
		{"WGET u", true},
		{`echo "$HOME"`, true},
	}
	for _, c := range cases {
		f, err := syntax.NewParser().Parse(strings.NewReader(c.src), "")
		if err != nil {
			t.Fatalf("parse %q: %v", c.src, err)
		}
		if got := prepassNeeded(f); got != c.want {
			t.Errorf("prepassNeeded(%q) = %v, want %v", c.src, got, c.want)
		}
	}
}

// TestLongArgPerformance: one argument near maxCommandBytes is answered in
// linear time, in every dialect, with the test and the default policies.
// Locally each input takes 30-130 ms (it took 0.4-10 s before #35); the
// bound is generous for slow, loaded CI runners (and x10 under the race
// detector), well under the 5 s hook watchdog.
func TestLongArgPerformance(t *testing.T) {
	scale := time.Duration(1)
	if raceEnabled {
		scale = 10
	}
	limit := time.Second * scale
	for _, pol := range perfPolicies() {
		e := New(pol.p)
		for _, u := range longArgUnits {
			for _, sh := range longArgShells {
				name := fmt.Sprintf("%s/%s/%s", pol.name, u.name, sh)
				req := shellReq(longArgCmd(u.unit, 256<<10-16))
				req.Shell = sh
				el, v := bestOf(e, req, 2)
				t.Logf("%s: %v %s %s", name, el, v.Decision, v.Rule)
				if el > limit {
					t.Errorf("%s: took %v, more than %v", name, el, limit)
				}
			}
		}
	}
}

// TestExpansionAmplification: parameter expansion can build words far
// longer than the command (a repeated long value, or a value doubled at
// every assignment). Such commands are denied as too-complex quickly; they
// took 7.5 s (past the hook watchdog) or ran out of memory before #35.
// A long value used a few times is still analysed.
func TestExpansionAmplification(t *testing.T) {
	var chain strings.Builder
	chain.WriteString("A0=" + strings.Repeat("a/", 512) + "; ")
	for i := 1; i <= 24; i++ {
		fmt.Fprintf(&chain, "A%d=$A%d$A%d; ", i, i-1, i-1)
	}
	chain.WriteString("cat $A24")
	big := strings.Repeat("a/", 32<<10)
	scale := time.Duration(1)
	if raceEnabled {
		scale = 10
	}
	cases := []struct {
		name, cmd string
		shells    []Shell
		want      Decision
		rule      string
	}{
		{"repeated value", `A="` + big + `"; cat` + strings.Repeat(" $A", 100), []Shell{ShellBash, ShellAuto}, Deny, RuleTooComplex},
		{"repeated quoted value", `A="` + big + `"; cat` + strings.Repeat(` "$A"`, 100), []Shell{ShellBash, ShellAuto}, Deny, RuleTooComplex},
		{"doubling chain", chain.String(), []Shell{ShellBash, ShellAuto}, Deny, RuleTooComplex},
		{"value used twice", `A="` + big + `"; cat "$A" "$A"`, []Shell{ShellBash}, Allow, ""},
		{"secret after a long value", `A="` + big + `"; cat "$A" .env`, []Shell{ShellBash}, Deny, "secret-file:"},
	}
	for _, pol := range perfPolicies() {
		e := New(pol.p)
		for _, c := range cases {
			for _, sh := range c.shells {
				req := shellReq(c.cmd)
				req.Shell = sh
				el, v := bestOf(e, req, 1)
				name := fmt.Sprintf("%s/%s/%s", pol.name, c.name, sh)
				t.Logf("%s: %v %s %s", name, el, v.Decision, v.Rule)
				if v.Decision != c.want || !strings.HasPrefix(v.Rule, c.rule) {
					t.Errorf("%s: got %s %s, want %s %s", name, v.Decision, v.Rule, c.want, c.rule)
				}
				if limit := time.Second * scale; el > limit {
					t.Errorf("%s: took %v, more than %v", name, el, limit)
				}
			}
		}
	}
}
