package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// interpWorstCaseShapes are interpreter programs that made the literal,
// format, process, Env and directory-listing scans quadratic.
var interpWorstCaseShapes = []struct{ name, prefix, unit, suffix string }{
	{"python many empty args", `python3 -c "f(`, `'',`, `)"`},
	{"python percent tuple", `python3 -c "x='%s' % (`, `'',`, `)"`},
	{"python format args", `python3 -c "'{}{}'.format(`, `'a',`, `)"`},
	{"python concat chain", `python3 -c "x=`, `'ab'+`, `'c'"`},
	{"node typeof process", `node -e '`, `typeof process;`, `'`},
	{"node process args", `node -e 'f(`, `process,`, `1)'`},
	{"perl use Env qw", `perl -e '`, `use Env qw(`, `'`},
	{"python nested listdir", `python3 -c "open(1);`, `os.listdir(`, `"`},
	{"python iterdir receivers", `python3 -c "open(1);`, `).iterdir(`, `"`},
	{"ruby getenv words", `ruby -e '`, `getenv `, `'`},
}

// interpWorstCase builds a shape at about size bytes.
func interpWorstCase(prefix, unit, suffix string, size int) string {
	n := (size - len(prefix) - len(suffix)) / len(unit)
	return prefix + strings.Repeat(unit, n) + suffix
}

// bestOf returns the fastest of n evaluations and the last verdict.
func bestOf(e *Engine, req Request, n int) (time.Duration, Verdict) {
	best := time.Hour
	var v Verdict
	for range n {
		start := time.Now()
		v = e.Evaluate(req)
		best = min(best, time.Since(start))
	}
	return best, v
}

// TestInterpPerformanceWorstCases: interpreter scanning must stay linear.
// The generic argument and command-pattern checks already cost something
// for one huge word given to any command; scanning it as code may only add
// a bounded, linear overhead on top of that baseline (the quadratic scans
// took seconds to minutes). Programs beyond maxCodeScan must be denied.
func TestInterpPerformanceWorstCases(t *testing.T) {
	e := New(testPolicy())
	scale := time.Duration(1)
	if raceEnabled {
		scale = 10 // the race detector slows execution roughly 10x
	}
	// Scanned programs: the quadratic versions took seconds already at 32 KB.
	for _, c := range interpWorstCaseShapes {
		cmd := interpWorstCase(c.prefix, c.unit, c.suffix, 32<<10)
		plainCmd := "foo " + cmd[strings.IndexAny(cmd, `"'`):] // same word, no interpreter
		for _, sh := range []Shell{ShellBash, ShellAuto} {
			name := fmt.Sprintf("%s 32KB (%s)", c.name, sh)
			req := shellReq(cmd)
			req.Shell = sh
			base := shellReq(plainCmd)
			base.Shell = sh
			baseline, _ := bestOf(e, base, 1)
			el, v := bestOf(e, req, 1)
			t.Logf("%s: %v (baseline %v) %s %s", name, el, baseline, v.Decision, v.Rule)
			if limit := 2*baseline + 150*time.Millisecond*scale; el > limit {
				t.Errorf("%s: took %v, more than %v (baseline %v)", name, el, limit, baseline)
			}
		}
	}
	// Oversized programs (near maxCommandBytes) are denied without scanning.
	for _, c := range interpWorstCaseShapes {
		name := c.name + " 250KB"
		el, v := bestOf(e, shellReq(interpWorstCase(c.prefix, c.unit, c.suffix, 250<<10)), 1)
		t.Logf("%s: %v %s %s", name, el, v.Decision, v.Rule)
		if ceiling := 2 * time.Second * scale; el > ceiling {
			t.Errorf("%s: took %v, more than %v", name, el, ceiling)
		}
		if v.Decision != Deny {
			t.Errorf("%s: want deny for an oversized program, got %s", name, v.Decision)
		}
	}
}
