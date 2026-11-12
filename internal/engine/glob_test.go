package engine

import "testing"

func TestSegmentsMatch(t *testing.T) {
	cases := []struct {
		arg, secret string
		dotglob     bool
		want        bool
	}{
		{".env", ".env", false, true},
		{".en*", ".env", false, true},
		{".e?v", ".env", false, true},
		{"[.]env", ".env", false, true},
		{".[e]nv", ".env", false, true},
		{"[!x]env", ".env", false, true},
		{"*", ".env", false, false}, // dotfile rule
		{"*", ".env", true, true},   // dotglob
		{"?env", ".env", false, false},
		{"*env", ".env", false, false},
		{"\x01env", ".env", false, true}, // dynamic part: no dotfile rule
		{"*", "*.pem", false, true},
		{"*.pem", "*.pem", false, true},
		{"*.PEM", "*.pem", false, false}, // callers lower-case first
		{"*.md", "id_rsa*", false, false},
		{"*.go", "id_rsa*", false, false},
		{"i*", "id_rsa*", false, true},
		{"*rsa*", "id_rsa*", false, true},
		{".e*", ".env.*", false, true},
		{"*.md", ".env.*", false, false},
		{"readme.md", ".env", false, false},
		{"[a-z]env", ".env", false, false},
		{"[[:punct:]]env", ".env", false, true},
		{`\*.pem`, "*.pem", false, true}, // a file literally named "*.pem" is a pem
		{"x[", "x[", false, true},
	}
	for _, c := range cases {
		got := segmentsMatch(parseSegment(c.arg), parseSegment(c.secret), c.dotglob)
		if got != c.want {
			t.Errorf("segmentsMatch(%q, %q, dotglob=%v) = %v, want %v", c.arg, c.secret, c.dotglob, got, c.want)
		}
	}
}

func TestPathsIntersect(t *testing.T) {
	cases := []struct {
		arg, secret string
		want        bool
	}{
		{"/home/u/proj/.env", "**/.env", true},
		{"/home/u/proj/a/b/.env", "**/.env", true},
		{"/home/u/proj/.env/x", "**/.env/**", true},
		{"/home/u/proj/config/secrets.yml", "/home/u/proj/config/secrets.yml", true},
		{"/home/u/proj/secrets.yml", "/home/u/proj/config/secrets.yml", false},
		{"**/secrets.yml", "/home/u/proj/config/secrets.yml", true},
		{"/home/u/proj/*/secrets.yml", "/home/u/proj/config/secrets.yml", true},
		{"/home/u/.ssh/id_ed25519", "/home/u/.ssh/**", true},
		{"/home/u/.sshx/id", "/home/u/.ssh/**", false},
		{"c:/proj/.env", "**/.env", true},
	}
	for _, c := range cases {
		if got := pathsIntersect(parsePath(c.arg), parsePath(c.secret), false); got != c.want {
			t.Errorf("pathsIntersect(%q, %q) = %v, want %v", c.arg, c.secret, got, c.want)
		}
	}
}

func TestGlobMatchString(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		{"rm -rf /", "rm -rf /", true},
		{"rm -rf /", "rm -rf /tmp", false},
		{`rm -rf /\*`, "rm -rf /*", true},
		{`rm -rf /\*`, "rm -rf /tmp", false},
		{"git push --force*", "git push --force-with-lease origin main", true},
		{"curl *", "curl -s http://x/a b", true},
		{"rm -rf /", "rm -rf \x00", true}, // runtime value could be "/"
		{"*_key", "api_key", true},
		{"*_key", "api_keys", false},
		{"*password*", "db_password_file", true},
	}
	for _, c := range cases {
		if got := globMatchString(c.pattern, c.subject); got != c.want {
			t.Errorf("globMatchString(%q, %q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}

func TestCleanInternal(t *testing.T) {
	cases := map[string]string{
		"/a/b/../c":    "/a/c",
		"/a/./b/":      "/a/b",
		"/..":          "/",
		"c:/a/../..":   "c:/",
		"c:/x/.env.":   "c:/x/.env",
		"/x/.env  ":    "/x/.env",
		"**/../x":      "**/x",
		"a/../../b":    "../b",
		"/a//b":        "/a/b",
		"/a/\\*/../b":  "/a/b",
		"/a/b\\./c":    "/a/b\\./c",
		"/home/u/../v": "/home/v",
	}
	for in, want := range cases {
		if got := cleanInternal(in); got != want {
			t.Errorf("cleanInternal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapDrivePrefixes(t *testing.T) {
	cases := map[string]string{
		"/c/users/x":         "c:/users/x",
		"/mnt/d/proj":        "d:/proj",
		"/cygdrive/e/x":      "e:/x",
		"//?/c:/x":           "/c:/x",
		"/proc/self/cwd/a":   "**/a",
		"/proc/123/root/etc": "/etc",
		"/usr/bin":           "/usr/bin",
	}
	for in, want := range cases {
		if got := mapDrivePrefixes(in); got != want {
			t.Errorf("mapDrivePrefixes(%q) = %q, want %q", in, got, want)
		}
	}
}
