package engine

import (
	"slices"
	"testing"
)

func TestDecodeLit(t *testing.T) {
	tests := []struct{ lang, in, want string }{
		{"python3", `\N{FULL STOP}env`, ".env"},
		{"python3", `\N{full stop}\N{LATIN SMALL LETTER E}nv`, ".env"},
		{"python3", `\N{SNOWMAN}x`, `N{SNOWMAN}x`}, // unknown name: left to ansiC (the raw code is still a decode primitive)
		{"node", `\u{2e}env`, ".env"},
		{"lua", `\46env`, ".env"},
		{"python3", `\x2eenv`, ".env"},
		{"ruby", `cat .e#{"nv"}`, "cat .env"},
		{"node", "${'.e'}nv", ".env"},
	}
	for _, tt := range tests {
		if got := decodeLit(tt.lang, tt.in); got != tt.want {
			t.Errorf("decodeLit(%q, %q) = %q, want %q", tt.lang, tt.in, got, tt.want)
		}
	}
}

func TestCodeLiteralsDerived(t *testing.T) {
	tests := []struct {
		code string
		want string // must be among the texts
	}{
		{`open('.e'+'nv','r')`, ".env"},
		{`''.join(['.e','nv'])`, ".env"},
		{`open('x.env'[1:])`, ".env"},
		{`open('vne.'[::-1])`, ".env"},
		{`'x.env'.slice(1)`, ".env"},
		{`'xx.envyy'.substring(2, 6)`, ".env"},
		{`'x.envy'.substr(1, 4)`, ".env"},
		{`open('%senv' % '.')`, ".env"},
		{`open('%s%s' % ('.e', 'nv'))`, ".env"},
		{`open('{}env'.format('.'))`, ".env"},
		{`open('{1}{0}'.format('nv', '.e'))`, ".env"},
		{`open(bytes([46,101,110,118]))`, ".env"},
		{`String.fromCharCode(46, 101, 110, 118)`, ".env"},
	}
	for _, tt := range tests {
		texts, _ := codeLiterals("python3", tt.code)
		if !slices.Contains(texts, tt.want) {
			t.Errorf("codeLiterals(%q) = %q, want it to contain %q", tt.code, texts, tt.want)
		}
	}
}

func TestCodeLiteralsBuilt(t *testing.T) {
	_, built := codeLiterals("php", `$f="get"."env";`)
	if !slices.Contains(built, "getenv") {
		t.Errorf("built = %q, want getenv", built)
	}
	_, built = codeLiterals("python3", `print('a', 'b')`)
	if !slices.Contains(built, "ab") || slices.Contains(built, "a") {
		t.Errorf("built = %q, want only multi-piece joins", built)
	}
}
