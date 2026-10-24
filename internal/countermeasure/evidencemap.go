package countermeasure

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"quarant/analyzer"
)

// EvidenceMap is the part of docs/assessment/evidence-map.json that decides
// whether an event is evidence of a violation: its type is one of a
// provision's signals, its evidence matches the provision's require_pattern
// and not its exclude_pattern. A countermeasure plan uses only such events:
// an event that the provision does not count (a CBC suite, a serial number
// sent in a URL) is no reason to stop traffic.
type EvidenceMap struct {
	provisions []mapProvision
}

type mapProvision struct {
	signals map[string]bool
	require *regexp.Regexp
	exclude *regexp.Regexp
}

func LoadEvidenceMap(path string) (*EvidenceMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Provisions []struct {
			Provision string   `json:"provision"`
			Signals   []string `json:"signals"`
			Require   string   `json:"require_pattern"`
			Exclude   string   `json:"exclude_pattern"`
		} `json:"provisions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m := &EvidenceMap{}
	for _, p := range doc.Provisions {
		mp := mapProvision{signals: map[string]bool{}}
		for _, s := range p.Signals {
			mp.signals[s] = true
		}
		if p.Require != "" {
			if mp.require, err = regexp.Compile(p.Require); err != nil {
				return nil, fmt.Errorf("%s require_pattern: %w", p.Provision, err)
			}
		}
		if p.Exclude != "" {
			if mp.exclude, err = regexp.Compile(p.Exclude); err != nil {
				return nil, fmt.Errorf("%s exclude_pattern: %w", p.Provision, err)
			}
		}
		m.provisions = append(m.provisions, mp)
	}
	return m, nil
}

// Counts reports whether some provision counts the event as evidence.
func (m *EvidenceMap) Counts(e analyzer.Event) bool {
	for _, p := range m.provisions {
		if !p.signals[e.Type] {
			continue
		}
		if p.require != nil && !p.require.MatchString(e.Evidence) {
			continue
		}
		if p.exclude != nil && p.exclude.MatchString(e.Evidence) {
			continue
		}
		return true
	}
	return false
}
