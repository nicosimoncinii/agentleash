package engine

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExpandLong(t *testing.T) {
	cases := []struct{ in, want string }{
		{"--f", "--force"},
		{"--rec", "--recursive"},
		{"--for", "--force"},
		{"--no-pres", "--no-preserve-root"},
		{"--inter=never", "--interactive=never"},
		{"--v", "--v"}, // ambiguous: --verbose / --version
		{"--", "--"},
		{"--recursive", "--recursive"},
		{"--bogus", "--bogus"},
	}
	for _, c := range cases {
		if got := expandLong(c.in, rmLongOpts); got != c.want {
			t.Errorf("expandLong(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDangerTarget(t *testing.T) {
	ctx := cmdCtx{home: "/home/u", homeInt: "/home/u", bases: []string{"/home/u/proj/src"}}
	win := cmdCtx{home: `C:\Users\u`, homeInt: "c:/users/u", bases: []string{"c:/users/u/proj"}}
	cases := []struct {
		ctx  cmdCtx
		in   string
		want string
	}{
		{ctx, "/", "/"},
		{ctx, "/*", "/"},
		{ctx, "/*/", "/"},
		{ctx, "/*/*", "/"},
		{ctx, "~", "~"},
		{ctx, "~/*", "~"},
		{ctx, "~/..", "~"},
		{ctx, "~/../..", "/"},
		{ctx, "/home", "~"},
		{ctx, "/home/u/..", "~"},
		{ctx, "../../../..", "/"},
		{ctx, "../../..", "~"}, // /home
		{ctx, "../..", "~"},    // /home/u
		{ctx, "..", ""},        // /home/u/proj
		{ctx, "*", ""},
		{ctx, "./build", ""},
		{ctx, "node_modules/*", ""},
		{ctx, "/tmp/*", ""},
		{ctx, "/tmp/build-*", ""},
		{ctx, "~/.cache/*", ""},
		{ctx, "~bob", ""},
		{ctx, "\x00", ""},
		{cmdCtx{homeInt: "/home/u"}, "..", ""}, // working directory unknown
		{win, "/c/*", "/"},
		{win, "/c/Users", "~"},
		{win, "/Users/u", "~"}, // homeRoot spells C:/Users/u as /Users/u
		{win, "../..", "~"},
		{win, "/d/data", ""},
		{cmdCtx{}, "~/..", "~"}, // home unknown
	}
	for _, c := range cases {
		if got := c.ctx.dangerTarget(c.in); got != c.want {
			t.Errorf("dangerTarget(%q, home %q) = %q, want %q", c.in, c.ctx.homeInt, got, c.want)
		}
	}
}

func TestCommandFormsNormalisation(t *testing.T) {
	ctx := cmdCtx{home: "/home/u", homeInt: "/home/u", bases: []string{"/home/u/proj"}}
	cases := []struct {
		in   string
		want string // one of the forms
		not  string // must not be a form ("" = skip)
	}{
		{"rm -rf /*", "rm -fr /", ""},
		{"rm -rf / /", "rm -fr /", ""},
		{"rm -rf ./build /", "rm -fr /", ""},
		{"rm --rec --for /", "rm -fr /", ""},
		{"rm -rf ~/..", "rm -fr ~", ""},
		{"rm -rf ~u", "rm -fr ~", ""},
		{"rm -rf ./build", "rm -fr build", "rm -fr ~"},
		{"rm -rf node_modules/*", "rm -fr node_modules/*", "rm -fr ~"},
		{"dd of=/dev/sda if=/dev/zero", "dd if=/dev/zero of=/dev/sda", ""},
		{"dd of=/dev/sda", "dd if=/dev/stdin of=/dev/sda", ""},
		{"git push --mirror", "git push --force", ""},
		{"git push --mirr", "git push --force", ""},
		{"git send-pack --force origin main", "git push --force origin main", ""},
		{"git reset --ha HEAD~1", "git reset --hard HEAD~1", ""},
		{"git reset --soft HEAD~1", "git reset --soft HEAD~1", "git reset --hard HEAD~1"},
		{"git push --follow-tags", "git push --follow-tags", "git push --force"},
	}
	for _, c := range cases {
		forms := commandFormsCtx(strings.Fields(c.in), ctx)
		if !containsStr(forms, c.want) {
			t.Errorf("forms(%q) = %q, missing %q", c.in, forms, c.want)
		}
		if c.not != "" && containsStr(forms, c.not) {
			t.Errorf("forms(%q) = %q, must not contain %q", c.in, forms, c.not)
		}
	}
}

func TestGitAliasExpansion(t *testing.T) {
	inline := commandFormsCtx([]string{"git", "-c", "alias.p=push -f", "p", "origin"}, plainCtx(""))
	if !containsStr(inline, "git push --force origin") {
		t.Errorf("inline alias forms = %q", inline)
	}
	aliases := newGitAliasSet()
	recordGitConfigAlias([]string{"git", "config", "--global", "alias.yolo", "push --force"}, aliases)
	recordGitConfigAlias([]string{"git", "config", "alias.co", "checkout"}, aliases)
	recordGitConfigAlias([]string{"git", "config", "alias.x", "!rm -rf"}, aliases)
	want := map[string][]string{"yolo": {"push --force"}, "co": {"checkout"}, "x": {"!rm -rf"}}
	if !reflect.DeepEqual(aliases.byName, want) {
		t.Fatalf("aliases = %v, want %v", aliases.byName, want)
	}
	ctx := cmdCtx{gitAliases: aliases}
	if f := commandFormsCtx([]string{"git", "yolo", "origin", "main"}, ctx); !containsStr(f, "git push --force origin main") {
		t.Errorf("script alias forms = %q", f)
	}
	if f := commandFormsCtx([]string{"git", "co", "main"}, ctx); containsStr(f, "git push --force main") {
		t.Errorf("benign alias forms = %q", f)
	}
	// Shell aliases run their text with the call's arguments appended.
	_, sh, ok := gitExpand([]string{"git", "x", "/", "a b", "$x"}, aliases, nil)
	if !ok || !reflect.DeepEqual(sh, []string{`rm -rf / a\ b \$x`}) {
		t.Errorf("shell alias commands = %q, ok %v", sh, ok)
	}
	_, sh, _ = gitExpand([]string{"git", "-c", "alias.y=co", "-c", "alias.co=!cat", "y", ".e*"}, nil, nil)
	if !reflect.DeepEqual(sh, []string{"cat .e*"}) {
		t.Errorf("chained inline shell alias = %q", sh)
	}
}

func TestGitAliasLimits(t *testing.T) {
	a := newGitAliasSet()
	for i := 0; i < maxGitAliasValues+1; i++ {
		a.add("alias.p", fmt.Sprintf("push %d", i))
	}
	if !a.overflowed() {
		t.Error("too many values for one alias must overflow")
	}
	a = newGitAliasSet()
	for i := 0; i < maxGitAliasNames+1; i++ {
		a.add(fmt.Sprintf("alias.n%d", i), "status")
	}
	if !a.overflowed() {
		t.Error("too many alias names must overflow")
	}
	// A dropped expansion must not fail open: without a budget, a runtime
	// form makes every git pattern match.
	var argv []string
	argv = append(argv, "git")
	for i := 0; i < 16; i++ {
		argv = append(argv, "-c", fmt.Sprintf("alias.a%d=a%d push", i%8, (i/8)%8))
	}
	argv = append(argv, "a0")
	forms := commandFormsCtx(argv, plainCtx(""))
	if !containsStr(forms, "git "+string(dynAny)) {
		t.Errorf("overflowing expansion forms = %q, want a runtime form", forms)
	}
	b := newBudget()
	commandFormsCtx(argv, cmdCtx{work: b})
	if !b.exhausted() {
		t.Error("overflowing expansion must exhaust the work budget (too-complex)")
	}
}

// fill repeats unit until the text is about size bytes.
func fill(size int, prefix string, unit func(i int) string, suffix string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for i := 0; ; i++ {
		u := unit(i)
		if b.Len()+len(u)+len(suffix) >= size {
			break
		}
		b.WriteString(u)
	}
	b.WriteString(suffix)
	return b.String()
}

func TestGitAliasBudget(t *testing.T) {
	type tcase struct {
		name, cmd string
		block     bool // must not be allowed
	}
	var cases []tcase
	for _, size := range []int{8 << 10, 64 << 10, maxCommandBytes - 16} {
		add := func(name string, block bool, prefix string, unit func(i int) string, suffix string) {
			cases = append(cases, tcase{fmt.Sprintf("%s %dKB", name, size>>10), fill(size, prefix, unit, suffix), block})
		}
		// Every name gets 8 values pointing at other names: the expansion
		// graph fans out at every step.
		add("fan-out definitions and uses", false, "", func(i int) string {
			return fmt.Sprintf("git config alias.a%d 'a%d push x'; git a%d y; ", i%8, (i/8)%8, i%8)
		}, "git a0")
		add("inline fan-out", false, "git", func(i int) string {
			return fmt.Sprintf(" -c alias.a%d='a%d push'", i%8, (i/8)%8)
		}, " a0 origin")
		add("inline fan-out force", true, "git", func(i int) string {
			return fmt.Sprintf(" -c alias.a%d='a%d push -f'", i%8, (i/8)%8)
		}, " a0 origin")
		add("many names", true, "", func(i int) string {
			return fmt.Sprintf("git config alias.n%d 'push -f'; ", i)
		}, "git n1")
		add("shell alias recursion", true, "", func(i int) string {
			return fmt.Sprintf("git config alias.s%d '!git s%d; git s%d'; ", i%8, (i/8)%8, (i/64)%8)
		}, "git s0 a b c")
		add("shell alias uses", false, "git config alias.s '!git status'; ", func(i int) string {
			return fmt.Sprintf("git s %d; ", i)
		}, "")
	}
	e := New(testPolicy())
	for _, c := range cases {
		req := shellReq(c.cmd)
		start := time.Now()
		v := e.Evaluate(req)
		el := time.Since(start)
		t.Logf("%s: %d bytes, %v, %s %s", c.name, len(c.cmd), el, v.Decision, v.Rule)
		limit := 200 * time.Millisecond
		if raceEnabled {
			limit *= 10
		}
		if el > limit {
			t.Errorf("%s: took %v (decision %s %s)", c.name, el, v.Decision, v.Rule)
		}
		if c.block && v.Decision == Allow {
			t.Errorf("%s: allowed; want deny (force push or too-complex)", c.name)
		}
	}
}

func TestStdinCodeRunner(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"sh", true},
		{"bash -s -- --yes", true},
		{"sh /dev/stdin", true},
		{"sh -", true},
		{"bash -x", true},
		{"sh ./install.sh", false},
		{"bash -c true", false},
		{"sudo -s", true},
		{"sudo -u root -i", true},
		{"sudo bash", false}, // the inner level is checked on its own
		{"su", true},
		{"su -c true", false},
		{"pwsh", true},
		{"pwsh -NoProfile -Command -", true},
		{"pwsh -File ./x.ps1", false},
		{"pwsh -Command Get-Date", false},
		{"python3", true},
		{"python3 -", true},
		{"python3 -m json.tool", false},
		{"node script.js", false},
		{"jq .name", false},
	}
	for _, c := range cases {
		if got := stdinCodeRunner(strings.Fields(c.in)); got != c.want {
			t.Errorf("stdinCodeRunner(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDownloadTargets(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"curl -o /tmp/i.sh https://x.invalid/i.sh", []string{"/tmp/i.sh"}},
		{"curl -fsSLo i.sh https://x.invalid/a", []string{"i.sh"}},
		{"curl --output=./i.sh https://x.invalid/a", []string{"i.sh"}},
		{"curl -O https://x.invalid/dl/i.sh?x=1", []string{"i.sh"}},
		{"curl https://x.invalid/i.sh", nil},
		{"wget https://x.invalid/i.sh", []string{"i.sh"}},
		{"wget -qO- https://x.invalid/i.sh", nil},
		{"wget -O i.sh https://x.invalid/a", []string{"i.sh"}},
		{"wget -P /tmp https://x.invalid/i.sh", []string{"/tmp/i.sh"}},
	}
	for _, c := range cases {
		if got := downloadTargets(strings.Fields(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("downloadTargets(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
