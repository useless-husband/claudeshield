package detect

import "sort"

// ahoCorasick finds every occurrence of many literal patterns in one pass.
//
// The token table of a busy workspace holds thousands of values, and each one
// must be found wherever it reappears. Searching for them one at a time costs
// O(patterns × text); this automaton costs O(text + matches). It is rebuilt in
// every hook process, so it is kept compact: per-node edges are a small sorted
// slice rather than a 256-entry table.
type ahoCorasick struct {
	nodes []acNode
}

type acNode struct {
	edges []acEdge
	fail  int32
	out   []int32 // patterns ending here, including via dictionary suffix links
	depth int32
}

type acEdge struct {
	b    byte
	next int32
}

func (n *acNode) child(b byte) (int32, bool) {
	e := n.edges
	i := sort.Search(len(e), func(i int) bool { return e[i].b >= b })
	if i < len(e) && e[i].b == b {
		return e[i].next, true
	}
	return 0, false
}

func newAhoCorasick(patterns []string) *ahoCorasick {
	ac := &ahoCorasick{nodes: []acNode{{}}}
	for pi, p := range patterns {
		if p == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(p); i++ {
			b := p[i]
			nx, ok := ac.nodes[cur].child(b)
			if !ok {
				nx = int32(len(ac.nodes))
				ac.nodes = append(ac.nodes, acNode{depth: ac.nodes[cur].depth + 1})
				e := ac.nodes[cur].edges
				j := sort.Search(len(e), func(k int) bool { return e[k].b >= b })
				e = append(e, acEdge{})
				copy(e[j+1:], e[j:])
				e[j] = acEdge{b, nx}
				ac.nodes[cur].edges = e
			}
			cur = nx
		}
		ac.nodes[cur].out = append(ac.nodes[cur].out, int32(pi))
	}
	// Breadth-first failure links.
	queue := make([]int32, 0, len(ac.nodes))
	for _, e := range ac.nodes[0].edges {
		ac.nodes[e.next].fail = 0
		queue = append(queue, e.next)
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range ac.nodes[u].edges {
			v := e.next
			f := ac.nodes[u].fail
			for {
				if nx, ok := ac.nodes[f].child(e.b); ok && nx != v {
					ac.nodes[v].fail = nx
					break
				}
				if f == 0 {
					ac.nodes[v].fail = 0
					break
				}
				f = ac.nodes[f].fail
			}
			ac.nodes[v].out = append(ac.nodes[v].out, ac.nodes[ac.nodes[v].fail].out...)
			queue = append(queue, v)
		}
	}
	return ac
}

// find calls fn(start, end, pattern) for every occurrence in s.
func (ac *ahoCorasick) find(s string, lens []int, fn func(start, end, pattern int)) {
	cur := int32(0)
	for i := 0; i < len(s); i++ {
		b := s[i]
		for {
			if nx, ok := ac.nodes[cur].child(b); ok {
				cur = nx
				break
			}
			if cur == 0 {
				break
			}
			cur = ac.nodes[cur].fail
		}
		for _, p := range ac.nodes[cur].out {
			end := i + 1
			fn(end-lens[p], end, int(p))
		}
	}
}
