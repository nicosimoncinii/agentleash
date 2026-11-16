package engine

import (
	"sync"
	"sync/atomic"

	"mvdan.cc/sh/v3/syntax"
)

// Resource limits. The engine must answer quickly for any input; anything
// beyond these limits is denied as "too complex to analyse safely" (fail
// closed) instead of being analysed slowly.
const (
	maxCommandBytes = 256 << 10 // raw command text
	maxSubstNesting = 24        // nested $(...), <(...), `...`
	maxPipeStages   = 256       // stages in all pipelines of one script
	maxScriptNodes  = 60000     // syntax nodes in one parsed script
	workBudget      = 50000     // abstract work units for one request (~tens of ms)
	maxBases        = 32        // possible working directories (cd targets)
)

const tooComplexReason = "the command is too complex to analyse safely (very long, deeply nested or too many pipeline stages), so it was blocked. Split it into smaller, simpler commands."

// maxExpandBytes bounds the text that parameter expansion produces in one
// request. Unlike literal text it is not bounded by maxCommandBytes:
// `cat $A $A ...` repeats a long value and `A1=$A0$A0; A2=$A1$A1; ...`
// doubles it at every step (out of memory within a 2 KB command, #35).
const maxExpandBytes = 1 << 20

// budget is a work counter shared by every evaluator of one request.
type budget struct {
	left     int
	hit      bool
	expanded int // bytes produced by parameter expansion
}

// expand records n bytes produced by parameter expansion, charged at one
// unit per KB, and reports whether work may continue. Beyond
// maxExpandBytes the budget is exhausted (too-complex).
func (b *budget) expand(n int) bool {
	if b == nil {
		return true
	}
	b.expanded += n
	if b.expanded > maxExpandBytes {
		b.left, b.hit = -1, true
	}
	return b.spend(n >> 10)
}

func newBudget() *budget { return &budget{left: workBudget} }

// spend consumes n units and reports whether work may continue.
func (b *budget) spend(n int) bool {
	if b == nil {
		return true
	}
	b.left -= n
	if b.left < 0 {
		b.hit = true
	}
	return !b.hit
}

func (b *budget) exhausted() bool { return b != nil && b.hit }

// maxPureCache bounds each pureCache: policy patterns and request homes are
// few, so a full cache only means a long-lived process saw many policies.
const maxPureCache = 1024

// pureCache memoises a pure function of its key across requests (policy
// pattern forms, parsed patterns, the internal form of a home directory),
// which were recomputed for every command or pipeline stage. Values are
// shared, so callers must not modify them. Safe for concurrent use.
type pureCache[K comparable, V any] struct {
	m sync.Map
	n atomic.Int64
}

func (c *pureCache[K, V]) get(k K, f func(K) V) V {
	if v, ok := c.m.Load(k); ok {
		return v.(V)
	}
	v := f(k)
	if c.n.Add(1) <= maxPureCache {
		c.m.Store(k, v)
	}
	return v
}

// tooComplex inspects a parsed script before analysis: nesting of
// substitutions, number of pipeline stages and of nodes.
func tooComplex(f *syntax.File) bool {
	var stack []bool
	depth, pipes, nodes := 0, 0, 0
	over := false
	syntax.Walk(f, func(n syntax.Node) bool {
		if over {
			return false
		}
		if n == nil {
			if len(stack) > 0 {
				if stack[len(stack)-1] {
					depth--
				}
				stack = stack[:len(stack)-1]
			}
			return true
		}
		nodes++
		nest := false
		switch x := n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			nest = true
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				pipes++
			}
		}
		if nest {
			depth++
		}
		stack = append(stack, nest)
		if depth > maxSubstNesting || pipes > maxPipeStages || nodes > maxScriptNodes {
			over = true
			return false
		}
		return true
	})
	return over
}
