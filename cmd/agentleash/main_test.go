package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	rev := []debug.BuildSetting{{Key: "vcs.revision", Value: "2ca91724e6e3b845d00176984305640a155c1f8d"}}
	tests := []struct {
		name                string
		version, commit     string
		info                *debug.BuildInfo
		ok                  bool
		wantVer, wantCommit string
	}{
		{"ldflags win", "0.3.0", "2ca9172", &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}, Settings: rev}, true, "0.3.0", "2ca9172"},
		{"go install module version", "dev", "none", &debug.BuildInfo{Main: debug.Module{Version: "v0.3.0"}}, true, "0.3.0", "none"},
		{"build from checkout", "dev", "none", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: rev}, true, "dev", "2ca9172"},
		{"short revision", "dev", "none", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}}}, true, "dev", "abc"},
		{"no build info", "dev", "none", nil, false, "dev", "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, c := resolveVersion(tt.version, tt.commit, tt.info, tt.ok)
			if v != tt.wantVer || c != tt.wantCommit {
				t.Errorf("resolveVersion() = %q, %q; want %q, %q", v, c, tt.wantVer, tt.wantCommit)
			}
		})
	}
}
