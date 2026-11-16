package engine

import (
	"math/rand"
	"strings"
	"testing"
)

// Reference (recursive, memoised) implementations of the glob intersection
// before #35. The production versions are iterative and linear in the
// argument length; these tests check that both agree.

func segmentsIntersectRef(a, b []gtok, dotglob bool) bool {
	dotRule := !dotglob && len(a) > 0 && a[0].shell && (a[0].kind == tStar || a[0].kind == tAny)
	n, m := len(a), len(b)
	memo := make(map[[3]int]bool)
	var f func(i, j int, started bool) bool
	f = func(i, j int, started bool) bool {
		if i == n && j == m {
			return true
		}
		st := 0
		if started {
			st = 1
		}
		key := [3]int{i, j, st}
		if v, ok := memo[key]; ok {
			return v
		}
		memo[key] = false
		noDot := dotRule && !started
		res := i < n && a[i].kind == tStar && f(i+1, j, started)
		if !res && j < m && b[j].kind == tStar && f(i, j+1, started) {
			res = true
		}
		if !res && i < n && j < m {
			ai, bj := &a[i], &b[j]
			switch {
			case ai.kind == tStar && bj.kind == tStar:
				if !started {
					res = f(i, j, true)
				}
			case ai.kind == tStar:
				res = admitsPair(bj, nil, noDot) && f(i, j+1, true)
			case bj.kind == tStar:
				res = admitsPair(ai, nil, noDot) && f(i+1, j, true)
			default:
				res = admitsPair(ai, bj, noDot) && f(i+1, j+1, true)
			}
		}
		memo[key] = res
		return res
	}
	return f(0, 0, false)
}

func segmentsMatchRef(a, b []gtok, dotglob bool) bool {
	if !segmentsIntersectRef(a, b, dotglob) {
		return false
	}
	if !hasStar(a) || !hasStar(b) {
		return true
	}
	for _, fill := range []rune{0, 'x'} {
		if segmentsIntersectRef(a, instantiate(b, fill), dotglob) || segmentsIntersectRef(instantiate(a, fill), b, true) {
			return true
		}
	}
	return false
}

func pathsIntersectRef(a, b gpath, dotglob bool) bool {
	n, m := len(a.segs), len(b.segs)
	memo := make(map[[2]int]int8)
	var g func(i, j int) bool
	g = func(i, j int) bool {
		if i == n && j == m {
			return true
		}
		key := [2]int{i, j}
		if v, ok := memo[key]; ok {
			return v == 1
		}
		memo[key] = 0
		res := false
		if i < n && a.segs[i].globstar {
			res = g(i+1, j) || (j < m && g(i, j+1))
		}
		if !res && j < m && b.segs[j].globstar {
			res = g(i, j+1) || (i < n && g(i+1, j))
		}
		if !res && i < n && j < m && !a.segs[i].globstar && !b.segs[j].globstar {
			res = segmentsMatchRef(a.segs[i].toks, b.segs[j].toks, dotglob) && g(i+1, j+1)
		}
		if res {
			memo[key] = 1
		}
		return res
	}
	return g(0, 0)
}

func globMatchStringRef(pattern, subject string) bool {
	return segmentsIntersectRef(parseFlat(subject, false), parseFlat(pattern, true), true)
}

// globAlphabet mixes literals, wildcards, classes, escapes, separators and
// dynamic markers.
var globAlphabet = []string{"a", "b", ".", "e", "*", "*", "?", "[a-e]", "[!.]", "[.]", `\*`, "/", "**", " ", "-", "\x00", "\x01", "é", "�", "\xff", "\xe2\x82", "\xac"}

func randGlob(r *rand.Rand, maxLen int) string {
	var b strings.Builder
	for range r.Intn(maxLen + 1) {
		b.WriteString(globAlphabet[r.Intn(len(globAlphabet))])
	}
	return b.String()
}

// TestGlobMatchersAgreeWithReference: the iterative matchers give the same
// answers as the recursive ones on random inputs.
func TestGlobMatchersAgreeWithReference(t *testing.T) {
	r := rand.New(rand.NewSource(35))
	for range 20000 {
		x, y := randGlob(r, 8), randGlob(r, 8)
		for _, dg := range []bool{false, true} {
			sa, sb := parseSegment(x), parseSegment(y)
			if got, want := segmentsIntersect(sa, sb, dg), segmentsIntersectRef(sa, sb, dg); got != want {
				t.Fatalf("segmentsIntersect(%q, %q, %v) = %v, want %v", x, y, dg, got, want)
			}
			if got, want := segmentsMatch(sa, sb, dg), segmentsMatchRef(sa, sb, dg); got != want {
				t.Fatalf("segmentsMatch(%q, %q, %v) = %v, want %v", x, y, dg, got, want)
			}
			pa, pb := parsePath(x), parsePath(y)
			if got, want := pathsIntersect(pa, pb, dg), pathsIntersectRef(pa, pb, dg); got != want {
				t.Fatalf("pathsIntersect(%q, %q, %v) = %v, want %v", x, y, dg, got, want)
			}
		}
		if got, want := globMatchString(x, y), globMatchStringRef(x, y); got != want {
			t.Fatalf("globMatchString(%q, %q) = %v, want %v", x, y, got, want)
		}
	}
}

func FuzzGlobMatchers(f *testing.F) {
	f.Add("*.pem", "id_rsa*", false)
	f.Add(".e*", ".env.*", true)
	f.Add("curl * | sh", "curl x | sh", false)
	f.Fuzz(func(t *testing.T, x, y string, dg bool) {
		if len(x) > 64 || len(y) > 64 {
			return
		}
		sa, sb := parseSegment(x), parseSegment(y)
		if got, want := segmentsMatch(sa, sb, dg), segmentsMatchRef(sa, sb, dg); got != want {
			t.Fatalf("segmentsMatch(%q, %q, %v) = %v, want %v", x, y, dg, got, want)
		}
		pa, pb := parsePath(x), parsePath(y)
		if got, want := pathsIntersect(pa, pb, dg), pathsIntersectRef(pa, pb, dg); got != want {
			t.Fatalf("pathsIntersect(%q, %q, %v) = %v, want %v", x, y, dg, got, want)
		}
		if got, want := globMatchString(x, y), globMatchStringRef(x, y); got != want {
			t.Fatalf("globMatchString(%q, %q) = %v, want %v", x, y, got, want)
		}
	})
}
