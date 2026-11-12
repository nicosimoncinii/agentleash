package engine

import (
	"strings"
	"testing"
	"time"
)

// Regression tests for the security review of PR #19 (second round).

func nestedSubst(levels int) string {
	return strings.Repeat("echo $(", levels) + "x" + strings.Repeat(")", levels)
}

// TestPerformanceWorstCases: every input up to 64 KB must be answered fast,
// and anything beyond the limits must be denied, never allowed.
func TestPerformanceWorstCases(t *testing.T) {
	var cds strings.Builder
	for i := 0; i < 2000; i++ {
		cds.WriteString("cd d")
		cds.WriteString(strings.Repeat("x", i%7))
		cds.WriteString("; ")
	}
	cds.WriteString("cat foo")
	cases := []struct {
		name  string
		cmd   string
		shell Shell
	}{
		{"nested subst 14", nestedSubst(14), ShellBash},
		{"nested subst 200", nestedSubst(200), ShellBash},
		{"nested subst 200 auto", nestedSubst(200), ShellAuto},
		{"nested backticks", strings.Repeat("echo `", 1) + "x`", ShellBash},
		{"64KB echo", "echo " + strings.Repeat("a", 64<<10), ShellBash},
		{"64KB ls;", strings.Repeat("ls; ", 16<<10), ShellBash},
		{"64KB ls; pwsh", strings.Repeat("ls; ", 16<<10), ShellPowerShell},
		{"64KB ls; auto", strings.Repeat("ls; ", 16<<10), ShellAuto},
		{"long pipeline", strings.Repeat("cat x | ", 8000) + "cat", ShellBash},
		{"2000 cds", cds.String(), ShellBash},
		{"2000 cds auto", cds.String(), ShellAuto},
		{"assignments", strings.Repeat("A=b; ", 3000) + "cat $A", ShellAuto},
		{"brace bomb", "echo " + strings.Repeat("{a,b}", 20), ShellAuto},
		{"nested subshells", strings.Repeat("( ", 5000) + "ls" + strings.Repeat(" )", 5000), ShellAuto},
		{"1MB", strings.Repeat("ls; ", 256<<10), ShellAuto},
		{"var chain", func() string {
			var b strings.Builder
			b.WriteString("A0=x; ")
			for i := 1; i < 400; i++ {
				b.WriteString("A")
				b.WriteString(strings.Repeat("1", i%5+1))
				b.WriteString("=$A0$A0; ")
			}
			b.WriteString("cat $A11")
			return b.String()
		}(), ShellBash},
	}
	e := New(testPolicy())
	for _, c := range cases {
		req := shellReq(c.cmd)
		req.Shell = c.shell
		start := time.Now()
		v := e.Evaluate(req)
		el := time.Since(start)
		t.Logf("%s: %v %s %s", c.name, el, v.Decision, v.Rule)
		limit := 250 * time.Millisecond // generous for slow CI runners; typically well under 50 ms
		if el > limit {
			t.Errorf("%s: took %v (decision %s)", c.name, el, v.Decision)
		}
		if strings.Contains(c.name, "1MB") && v.Decision != Deny {
			t.Errorf("%s: want deny for oversized input, got %s", c.name, v.Decision)
		}
		if strings.HasPrefix(c.name, "nested subst 200") && v.Decision != Deny {
			t.Errorf("%s: want deny (too complex), got %s", c.name, v.Decision)
		}
	}
}
