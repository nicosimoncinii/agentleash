package engine

import (
	"strings"
	"testing"
)

const protRule = RuleProtected + ":"

func TestProtectedShellBash(t *testing.T) {
	cases := []tc{
		// writes through the shell
		{"echo 'version: 1' > .agentleash.yaml", Deny, protRule + "./.agentleash.yaml"},
		{"echo x >> .claude/settings.json", Deny, protRule + "./.claude/settings.json"},
		{"sed -i 's/deny/x/' .agentleash.yaml", Deny, protRule},
		{"sed -n 'w .agentleash.yaml' notes.txt", Deny, protRule},
		{"rm .agentleash.yaml", Deny, protRule},
		{"rm -rf .claude", Deny, protRule},
		{"rm -rf .codex/", Deny, protRule},
		{"mv .agentleash.yaml /tmp/x", Deny, protRule},
		{"cp /tmp/evil.yaml .agentleash.yaml", Deny, protRule},
		{"tee .codex/hooks.json < /tmp/h", Deny, protRule},
		{"truncate -s0 .codex/config.toml", Deny, protRule},
		{"git checkout -- .agentleash.yaml", Deny, protRule},
		{"git restore .claude/settings.json", Deny, protRule},
		{"cd .claude && rm settings.json", Deny, protRule},
		{"rm .agent*", Deny, protRule},
		{"rm .claude/*.json", Deny, protRule},
		{"echo '{}' > ~/.claude/settings.json", Deny, protRule + "~/.claude/settings.json"},
		{"rm ~/.codex/config.toml", Deny, protRule},
		{"python3 -c \"open('.agentleash.yaml','w').write('version: 1')\"", Deny, protRule},
		{"node -e \"require('fs').writeFileSync('.claude/settings.json','{}')\"", Deny, protRule},
		{"bash -c 'rm .agentleash.yaml'", Deny, protRule},
		{"yq -i '.commands.deny = []' .agentleash.yaml", Deny, protRule},
		{"awk '{print}' .agentleash.yaml > /tmp/x", Deny, protRule},
		{"cat .agentleash.yaml > /tmp/copy", Deny, protRule},
		{"sed -e 1d -i .agentleash.yaml", Deny, protRule},
		{"sed -ni 1p .agentleash.yaml", Deny, protRule},
		{"s\\ed -i 1d .agentleash.yaml", Deny, protRule},
		{"sed -f evil.sed .agentleash.yaml", Deny, protRule},
		{"find . -name .agentleash.yaml -delete", Deny, protRule},
		{"git -c core.pager='rm .agentleash.yaml' log .agentleash.yaml", Deny, protRule},
		{"git diff --output=.agentleash.yaml", Deny, protRule},
		{"cat .agentleash.yaml | sh", Deny, ""},
		{"find . -delete", Deny, protRule},
		{"find build -name '*.o' -delete", Allow, ""},
		{"cat .agentleash.yaml & rm x", Deny, protRule},
		{"cat $(echo .agentleash.yaml)", Deny, ""},
		{"GIT_EXTERNAL_DIFF=x git diff .agentleash.yaml", Deny, protRule},
		{"bash -lc 'cat .agentleash.yaml; rm .agentleash.yaml'", Deny, protRule},
		// reads stay allowed
		{"cat .agentleash.yaml", Allow, ""},
		{"head -n 20 .claude/settings.json", Allow, ""},
		{"sed -n '1,200p' .codex/config.toml", Allow, ""},
		{"sed -n 1,50p .agentleash.yaml | grep deny", Allow, ""},
		{"grep -n deny .agentleash.yaml", Allow, ""},
		{"rg protect .agentleash.yaml", Allow, ""},
		{"git diff .agentleash.yaml", Allow, ""},
		{"git --no-pager log -p -- .agentleash.yaml", Allow, ""},
		{"git add .agentleash.yaml && git commit -m 'policy: tighten'", Allow, ""},
		{"ls -la .claude", Allow, ""},
		{"jq . .claude/settings.json", Allow, ""},
		{"cat .codex/hooks.json 2>/dev/null || true", Allow, ""},
		{"bash -lc 'sed -n 1,200p .codex/config.toml'", Allow, ""},
		{"wc -l .agentleash.yaml > /dev/null", Allow, ""},
		// unrelated files
		{"echo hi > settings.json", Allow, ""},
		{"rm -rf build", Allow, ""},
		{"echo x > src/.claude/settings.json", Allow, ""},
	}
	runCases(t, ShellBash, cases)
}

func TestProtectedPowerShell(t *testing.T) {
	cases := []tc{
		{"Set-Content .agentleash.yaml 'version: 1'", Deny, protRule},
		{"Remove-Item -Recurse .claude", Deny, protRule},
		{"'x' | Out-File .codex\\config.toml", Deny, protRule},
		{"Get-Content .agentleash.yaml | Set-Content x.yaml", Deny, protRule},
		{"gc .agentleash.yaml > copy.txt", Deny, protRule},
		{"Get-Content .agentleash.yaml", Allow, ""},
		{"Get-Content .codex\\config.toml | Select-String hooks", Allow, ""},
		{"cat .claude\\settings.json", Allow, ""},
	}
	runCases(t, ShellPowerShell, cases)
}

func TestProtectedAuto(t *testing.T) {
	cases := []tc{
		{"rm .agentleash.yaml", Deny, protRule},
		{"cat \"x\\\"; Remove-Item .agentleash.yaml; \\\"\"", Deny, ""},
		{"type .agentleash.yaml & del .agentleash.yaml", Deny, protRule},
		{"cat .agentleash.yaml", Allow, ""},
		{"bash -lc 'sed -n 1,200p .codex/config.toml'", Allow, ""},
	}
	runCases(t, ShellAuto, cases)
}

func TestProtectedFileTools(t *testing.T) {
	e := New(testPolicy())
	for _, c := range []struct {
		tool  ToolKind
		paths []string
		want  Decision
	}{
		{ToolWrite, []string{testRoot + "/.agentleash.yaml"}, Deny},
		{ToolWrite, []string{testRoot + "/.claude/settings.local.json"}, Deny},
		{ToolWrite, []string{testHome + "/.codex/config.toml"}, Deny},
		{ToolWrite, []string{testRoot + "/src/main.go"}, Allow},
		{ToolRead, []string{testRoot + "/.agentleash.yaml"}, Allow},
		{ToolSearch, []string{testRoot + "/.claude"}, Allow},
	} {
		v := e.Evaluate(Request{Tool: c.tool, Paths: c.paths, Cwd: testRoot, ProjectRoot: testRoot, Home: testHome})
		if v.Decision != c.want {
			t.Errorf("%s %v = %s (%s), want %s", c.tool, c.paths, v.Decision, v.Rule, c.want)
		}
	}
	// apply_patch paths carried by a shell call are writes, even for a reader.
	v := e.Evaluate(Request{Tool: ToolShell, Shell: ShellAuto, Command: "cat README.md",
		Paths: []string{testRoot + "/.codex/hooks.json"}, Cwd: testRoot, ProjectRoot: testRoot, Home: testHome})
	if v.Decision != Deny || !strings.HasPrefix(v.Rule, protRule) {
		t.Errorf("apply_patch on .codex/hooks.json = %s (%s), want deny", v.Decision, v.Rule)
	}
}

func TestProtectedPolicyExtra(t *testing.T) {
	p := testPolicy()
	p.Protect.Files = []string{"Makefile", "ci/**"}
	e := New(p)
	for cmd, want := range map[string]Decision{
		"echo x >> Makefile":    Deny,
		"rm -rf ci":             Deny,
		"cat Makefile":          Allow,
		"echo x >> README.md":   Allow,
		"rm .agentleash.yaml":   Deny,
		"cat ci/pipeline.yml":   Allow,
		"sed -i 1d ci/a.yml":    Deny,
		"cat .agentleash.yaml":  Allow,
		"touch .agentleash.yml": Allow,
	} {
		if v := e.Evaluate(shellReq(cmd)); v.Decision != want {
			t.Errorf("%q = %s (%s), want %s", cmd, v.Decision, v.Rule, want)
		}
	}
}

func TestSedScriptReadOnly(t *testing.T) {
	for s, want := range map[string]bool{
		"1,200p": true, "$p": true, "10q": true, "1,5p;8p": true, "p": true, "=": true,
		"w x": false, "1e id": false, "s/a/b/w x": false, "r /etc/passwd": false, "1,2s/a/b/": false,
	} {
		if got := sedScriptRe.MatchString(s); got != want {
			t.Errorf("sed script %q read-only = %v, want %v", s, got, want)
		}
	}
}

// Findings of the #17 review.
func TestProtectedReviewBypasses(t *testing.T) {
	runCases(t, ShellBash, []tc{
		// 1. brace and glob expansion around option checks
		{"find .agentleash.yaml {-delete,-print}", Deny, protRule},
		{"sed -n -e 1p {-i,} .agentleash.yaml", Deny, protRule},
		{"git diff {--output=.agentleash.yaml,}", Deny, protRule},
		{"git diff {--output,--stat}=.agentleash.yaml", Deny, protRule},
		{"bash -c 'find .agentleash.yaml {-delete,}'", Deny, protRule},
		{"rg {--pre=sh,x} y .agentleash.yaml", Deny, protRule},
		{"find .agentleash.yaml -dele?", Deny, protRule},
		// 3. agentleash's own writers
		{"agentleash apply --remove", Deny, protRule},
		{"./agentleash apply --agent claude --remove", Deny, protRule},
		{"agentleash init --force", Deny, protRule},
		{"agentleash doctor", Allow, ""},
		{"agentleash version", Allow, ""},
		{"agentleash --help", Allow, ""},
		// 4. ancestors of the project
		{"rm -rf .", Deny, ""},
		{"rm -rf .claude/..", Deny, ""},
		{"rm -rf ../proj", Deny, ""},
		{"rm -rf /home/u/proj", Deny, ""},
		{"mv /home/u/proj /tmp/x", Deny, ""},
		// 5. file lists only known at runtime
		{"ls -A | xargs rm -f", Ask, ""},
		{"rm $(cat list.txt)", Ask, ""},
		{"rm -rf \"$DIR\"", Ask, ""},
		// 8. common reads
		{"sed -n '/hooks/,+5p' .codex/config.toml", Allow, ""},
		{"sed -n '1,40p;/deny/p' .agentleash.yaml", Allow, ""},
		{"[[ -f .agentleash.yaml ]] && cat .agentleash.yaml", Allow, ""},
		{"if [ -f .agentleash.yaml ]; then cat .agentleash.yaml; fi", Allow, ""},
		{"type .agentleash.yaml", Allow, ""},
		{"if [ -f .agentleash.yaml ]; then rm .agentleash.yaml; fi", Deny, protRule},
		{"[[ -f $(rm .agentleash.yaml) ]]", Deny, ""},
	})
	runCases(t, ShellPowerShell, []tc{
		// 2. PowerShell 5.1 passes embedded quotes to native programs
		{`git diff '--src-prefix=a/"" --output=.agentleash.yaml ""--dst-prefix=b/' f`, Deny, protRule},
		{`sed -n -e 1p .agentleash.yaml 'x"" -i ""-s'`, Deny, protRule},
		{"agentleash apply --remove", Deny, protRule},
		{"Get-ChildItem -Force | Remove-Item -Recurse -Force", Ask, ""},
		{`Get-Content .claude\settings.json | ConvertFrom-Json`, Allow, ""},
	})
	runCases(t, ShellAuto, []tc{
		{"sed -n 1p .agentleash.yaml 'x -s -i'", Deny, protRule},
		{"cat .agentleash.yaml 2>/dev/null", Allow, ""},
		{"type .agentleash.yaml", Allow, ""},
		{"bash -lc 'sed -n 1,200p .codex/config.toml'", Allow, ""},
	})
}
