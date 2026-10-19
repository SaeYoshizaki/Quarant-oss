// Package corroborate overlays Quarant's own events with events another
// analyser (Zeek) produced from the same capture, connection by
// connection: the same flow key, the same event type, and capture times
// that Quarant would have treated as one flow.
//
//   - Both reported it: Quarant's event is kept, records both sources and
//     its confidence goes up one step. The other analyser's copies are
//     dropped.
//   - Only Quarant: kept as it is, source quarant.
//   - Only the other analyser: kept as evidence when its confidence is
//     medium or high. A low-confidence event (Zeek saw only a name, O1) is
//     not evidence on its own and goes to Held instead.
package corroborate

import (
	"sort"
	"strings"
	"time"

	"quarant/analyzer"
)

const Quarant = "quarant"

// Result is the overlaid output.
type Result struct {
	// Events are the evidence: Quarant's events, and the other analyser's
	// events that Quarant did not report, if confident enough to stand alone.
	Events []analyzer.Event
	// Held are the other analyser's low-confidence events that Quarant did
	// not report.
	Held []analyzer.Event
	// Counts per event type.
	Counts map[string]*Count
}

type Count struct {
	Both        int `json:"both"`
	QuarantOnly int `json:"quarant_only"`
	OtherOnly   int `json:"other_only"`
	OtherHeld   int `json:"other_held"`
	// OtherAbsorbed counts the other analyser's events folded into a
	// Quarant event. Quarant reports a type once per flow; Zeek reports it
	// per request or per connection on a reused key.
	OtherAbsorbed int `json:"other_absorbed"`
}

type groupKey struct{ flow, typ string }

type report struct {
	at    time.Time
	other bool
	i     int
}

// Merge overlays other onto quarant. Neither slice is modified.
//
// Reports of one type on one flow key are put in time order and split
// where nothing was reported for analyzer.FlowIdleTimeout: Quarant keeps a
// flow that long and reports each rule once in it, so the reports inside
// one span are about the same flow as far as Quarant is concerned.
func Merge(quarant, other []analyzer.Event) Result {
	groups := map[groupKey][]report{}
	for i, e := range quarant {
		if e.FlowKey != "" && !e.Debug {
			k := groupKey{e.FlowKey, e.Type}
			groups[k] = append(groups[k], report{e.Timestamp, false, i})
		}
	}
	for i, e := range other {
		if e.FlowKey != "" {
			k := groupKey{e.FlowKey, e.Type}
			groups[k] = append(groups[k], report{e.Timestamp, true, i})
		}
	}
	corroborated := map[int][]string{}
	absorbed := make([]bool, len(other))
	res := Result{Counts: map[string]*Count{}}
	count := func(typ string) *Count {
		c := res.Counts[typ]
		if c == nil {
			c = &Count{}
			res.Counts[typ] = c
		}
		return c
	}
	for k, rs := range groups {
		sort.SliceStable(rs, func(a, b int) bool { return rs[a].at.Before(rs[b].at) })
		for start := 0; start < len(rs); {
			end := start + 1
			for end < len(rs) && rs[end].at.Sub(rs[end-1].at) <= analyzer.FlowIdleTimeout {
				end++
			}
			span := rs[start:end]
			start = end
			var qs []int
			var by []string
			for _, r := range span {
				if r.other {
					by = appendUnique(by, sourceName(other[r.i]))
				} else {
					qs = append(qs, r.i)
				}
			}
			if len(qs) == 0 || len(by) == 0 {
				continue
			}
			sort.Strings(by)
			for _, i := range qs {
				corroborated[i] = by
			}
			for _, r := range span {
				if r.other {
					absorbed[r.i] = true
					count(k.typ).OtherAbsorbed++
				}
			}
		}
	}

	for i, e := range quarant {
		e.Sources = []string{Quarant}
		if by := corroborated[i]; by != nil {
			e.Sources = append(e.Sources, by...)
			e.Confidence = raise(e.Confidence)
			e.Limitation = joinSentence(e.Limitation, "Another parser ("+strings.Join(by, ", ")+") reported the same on this connection; the agreement checks the parse, not whether the finding matters.")
			count(e.Type).Both++
		} else if !e.Debug {
			count(e.Type).QuarantOnly++
		}
		res.Events = append(res.Events, e)
	}
	for i, e := range other {
		if absorbed[i] {
			continue
		}
		e.Sources = []string{sourceName(e)}
		if e.Confidence == "low" {
			res.Held = append(res.Held, e)
			count(e.Type).OtherHeld++
			continue
		}
		res.Events = append(res.Events, e)
		count(e.Type).OtherOnly++
	}
	sort.SliceStable(res.Events, func(a, b int) bool { return res.Events[a].Timestamp.Before(res.Events[b].Timestamp) })
	sort.SliceStable(res.Held, func(a, b int) bool { return res.Held[a].Timestamp.Before(res.Held[b].Timestamp) })
	return res
}

func sourceName(e analyzer.Event) string {
	if e.Source == "" {
		return "other"
	}
	return e.Source
}

// raise moves a confidence up one step: low → medium → high.
func raise(c string) string {
	switch c {
	case "low":
		return "medium"
	case "medium":
		return "high"
	}
	return c
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func joinSentence(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}
