//go:build !race

package engine

// raceEnabled reports whether the race detector is on; it slows code ~10x.
const raceEnabled = false
