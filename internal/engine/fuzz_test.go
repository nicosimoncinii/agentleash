package engine

import "testing"

// FuzzEvaluate checks the engine never panics past its recover and always
// returns a well-formed verdict, for every dialect.
func FuzzEvaluate(f *testing.F) {
	for _, s := range []string{
		"cat .env", "echo ${X:-.env}", "find . -name '*.go' -exec cat {} +", "$(echo a | base64 -d)",
		"Get-Content ('.e'+'nv')", "cmd /c type .env", "python3 -c \"open('.env')\"", "a=(1 2); ${a[@]}",
		"@'\nx\n'@", "\"$(", "[x", "`", "eval $(", "{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}",
	} {
		f.Add(s)
	}
	// Interpreter scans that used to be quadratic (see interp_perf_test.go).
	for _, c := range interpWorstCaseShapes {
		f.Add(interpWorstCase(c.prefix, c.unit, c.suffix, 4<<10))
	}
	e := New(testPolicy())
	f.Fuzz(func(t *testing.T, cmd string) {
		for _, sh := range []Shell{ShellBash, ShellPowerShell, ShellAuto} {
			req := shellReq(cmd)
			req.Shell = sh
			v := e.Evaluate(req)
			if v.Rule == RuleInternal {
				t.Fatalf("internal error for %q (%s): %s", cmd, sh, v.Reason)
			}
			switch v.Decision {
			case Allow:
			case Deny, Ask:
				if v.Reason == "" || v.Rule == "" {
					t.Fatalf("verdict without reason/rule: %+v", v)
				}
			default:
				t.Fatalf("bad decision %q", v.Decision)
			}
		}
	})
}
