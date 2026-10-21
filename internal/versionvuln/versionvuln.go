// Package versionvuln matches software versions that devices name in their
// traffic against the CVEs of knowledge/component_cves.json (NVD affected
// version ranges, CISA KEV). Matching is local; the knowledge file is built
// by scripts/knowledge/fetch_component_cves.py.
//
// A match is a candidate, not a finding of vulnerability: the named version
// may not be the one running, vendors backport fixes without changing the
// version string, and the vulnerable feature may not be built in.
package versionvuln

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"quarant/knowledge"
)

type Range struct {
	Exact          string `json:"exact"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}

type CVE struct {
	ID        string  `json:"id"`
	Published string  `json:"published"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	KEV       bool    `json:"kev"`
	Ranges    []Range `json:"ranges"`
}

type Product struct {
	Names      []string `json:"names"`
	CPE        string   `json:"cpe"`
	MinVersion string   `json:"min_version"`
	// Suite: the product bundles many programs (BusyBox), so a CVE may
	// concern one the device does not build in.
	Suite bool  `json:"suite"`
	CVEs  []CVE `json:"cves"`
}

type DB struct {
	Fetched  string    `json:"fetched"`
	Products []Product `json:"products"`
	byName   map[string]*Product
}

// Load reads the embedded knowledge file.
func Load() (*DB, error) {
	raw, err := fs.ReadFile(knowledge.Files, "component_cves.json")
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(raw []byte) (*DB, error) {
	var db DB
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("component_cves.json: %w", err)
	}
	db.byName = map[string]*Product{}
	for i := range db.Products {
		for _, n := range db.Products[i].Names {
			db.byName[strings.ToLower(n)] = &db.Products[i]
		}
	}
	return &db, nil
}

// Hit is one CVE whose affected range contains the observed version.
type Hit struct {
	CVE CVE
	// Partial: the observed version has fewer parts than the range bound
	// ("2.7" against "2.7.3"), so it may or may not be affected.
	Partial bool
	// DaysPublished: days from the CVE's publication to the observation.
	DaysPublished int
}

// Match returns the CVEs published before observed whose ranges contain
// version, most severe first. A CVE published after the capture is left
// out: it says nothing about how the device was maintained at the time.
func (db *DB) Match(name, version string, observed time.Time) (p *Product, hits []Hit) {
	p = db.byName[strings.ToLower(strings.TrimSpace(name))]
	if p == nil || parse(version) == nil {
		return nil, nil
	}
	if p.MinVersion != "" && compare(version, p.MinVersion) < 0 {
		return p, nil
	}
	for _, c := range p.CVEs {
		pub, err := time.Parse("2006-01-02", c.Published)
		if err != nil || !pub.Before(observed) {
			continue
		}
		in, partial := false, false
		for _, r := range c.Ranges {
			ok, part := contains(r, version)
			if ok && (!in || partial && !part) {
				in, partial = true, part
			}
		}
		if in {
			hits = append(hits, Hit{CVE: c, Partial: partial, DaysPublished: int(observed.Sub(pub).Hours() / 24)})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Partial != hits[j].Partial {
			return !hits[i].Partial
		}
		if hits[i].CVE.KEV != hits[j].CVE.KEV {
			return hits[i].CVE.KEV
		}
		return hits[i].CVE.Score > hits[j].CVE.Score
	})
	return p, hits
}

// contains reports whether version lies in r. partial is set when the
// version is shorter than a bound it was compared with.
func contains(r Range, version string) (ok, partial bool) {
	n := len(parse(version))
	short := func(b string) bool { return b != "" && n < len(parse(b)) }
	if r.Exact != "" {
		if short(r.Exact) {
			return strings.HasPrefix(r.Exact, version+"."), true
		}
		return compare(version, r.Exact) == 0, false
	}
	if r.StartIncluding == "" && r.StartExcluding == "" && r.EndIncluding == "" && r.EndExcluding == "" {
		return false, false
	}
	if r.StartIncluding != "" && compare(version, r.StartIncluding) < 0 ||
		r.StartExcluding != "" && compare(version, r.StartExcluding) <= 0 ||
		r.EndIncluding != "" && compare(version, r.EndIncluding) > 0 ||
		r.EndExcluding != "" && compare(version, r.EndExcluding) >= 0 {
		return false, false
	}
	return true, short(r.StartIncluding) || short(r.StartExcluding) || short(r.EndIncluding) || short(r.EndExcluding)
}

var numRe = regexp.MustCompile(`\d+`)

// parse takes the numeric parts of a version ("2016.73" -> [2016 73],
// "7.4p1" -> [7 4 1]).
func parse(v string) []int {
	var out []int
	for _, s := range numRe.FindAllString(v, -1) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// compare orders versions part by part; missing parts count as 0.
func compare(a, b string) int {
	x, y := parse(a), parse(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1
			}
			return 1
		}
	}
	return 0
}
