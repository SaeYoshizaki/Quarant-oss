package device

import (
	"sort"
	"strings"
)

// observedIndex answers "which observed value (host, path, User-Agent, ...)
// contains one of these keywords" without lower-casing and scanning every
// value on each identity recompute. A device under a web scan collects
// thousands of distinct paths, and the identity is recomputed on every
// request, which made the analysis quadratic in the number of requests
// (STATUS known issue 10).
//
// Values keep their insertion order, and a keyword query picks the earliest
// value that contains any of the keywords. The former loop over the Go map
// picked one at random when several values matched.
type observedIndex struct {
	values []string
	lower  []string
	seen   map[string]bool
	// first: keyword -> index of the earliest value containing it, or -1
	// when none of the first upto[keyword] values does.
	first map[string]int
	upto  map[string]int
}

func newObservedIndex() *observedIndex {
	return &observedIndex{seen: map[string]bool{}, first: map[string]int{}, upto: map[string]int{}}
}

func (ix *observedIndex) add(v string) {
	if ix.seen[v] {
		return
	}
	ix.seen[v] = true
	ix.values = append(ix.values, v)
	ix.lower = append(ix.lower, strings.ToLower(v))
}

func (ix *observedIndex) firstIndex(k string) int {
	if i, ok := ix.first[k]; ok && i >= 0 {
		return i
	}
	for j := ix.upto[k]; j < len(ix.lower); j++ {
		if strings.Contains(ix.lower[j], k) {
			ix.first[k] = j
			ix.upto[k] = j
			return j
		}
	}
	ix.first[k] = -1
	ix.upto[k] = len(ix.lower)
	return -1
}

// match returns the earliest value containing any of keywords and, for that
// value, the first keyword (in list order, lower-cased and trimmed) it
// contains.
func (ix *observedIndex) match(keywords []string) (value, keyword string, ok bool) {
	best := -1
	for _, kw := range keywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k == "" {
			continue
		}
		if i := ix.firstIndex(k); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	if best < 0 {
		return "", "", false
	}
	for _, kw := range keywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k != "" && strings.Contains(ix.lower[best], k) {
			return ix.values[best], k, true
		}
	}
	return "", "", false
}

// noteObserved records a value written to one of the observed maps, in the
// order it was seen.
func (d *DeviceProfile) noteObserved(kind, value string) {
	if d.observed == nil {
		d.observed = map[string]*observedIndex{}
	}
	ix := d.observed[kind]
	if ix == nil {
		ix = newObservedIndex()
		d.observed[kind] = ix
	}
	ix.add(value)
}

// observedIndexFor returns the index of one observed map. Values put into the
// map without noteObserved (tests, profiles built elsewhere) are added in
// sorted order; a map that no longer holds what was indexed is re-indexed.
func (d *DeviceProfile) observedIndexFor(kind string, observed map[string]bool) *observedIndex {
	if d.observed == nil {
		d.observed = map[string]*observedIndex{}
	}
	ix := d.observed[kind]
	if ix == nil || len(ix.values) > len(observed) {
		ix = newObservedIndex()
		d.observed[kind] = ix
	}
	if len(ix.values) != len(observed) {
		var missing []string
		for v := range observed {
			if !ix.seen[v] {
				missing = append(missing, v)
			}
		}
		sort.Strings(missing)
		for _, v := range missing {
			ix.add(v)
		}
	}
	return ix
}
