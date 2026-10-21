package versionvuln

import (
	"testing"
	"time"
)

const sample = `{"fetched":"2026-10-21","products":[
 {"names":["dropbear"],"cpe":"dropbear_ssh_project:dropbear_ssh","cves":[
  {"id":"CVE-2016-7406","published":"2017-03-03","severity":"CRITICAL","score":9.8,"ranges":[{"versionEndIncluding":"2016.73"}]},
  {"id":"CVE-2020-0001","published":"2020-01-01","severity":"HIGH","score":7.5,"ranges":[{"versionEndExcluding":"2020.79"}]}]},
 {"names":["udhcp","busybox"],"cpe":"busybox:busybox","min_version":"1.0","cves":[
  {"id":"CVE-2018-1000500","published":"2018-06-26","severity":"HIGH","score":8.1,"ranges":[{"versionEndExcluding":"1.32.0"}]},
  {"id":"CVE-2016-2148","published":"2016-02-09","severity":"CRITICAL","score":9.8,"ranges":[{"versionEndExcluding":"1.25.0"}]}]},
 {"names":["gSOAP"],"cpe":"genivia:gsoap","cves":[
  {"id":"CVE-2017-9765","published":"2017-07-20","severity":"HIGH","score":8.1,"ranges":[{"exact":"2.7.0"},{"exact":"2.8.47"}]}]}]}`

var march2018 = time.Date(2018, 3, 20, 0, 0, 0, 0, time.UTC)

func ids(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.CVE.ID)
	}
	return out
}

func TestMatch(t *testing.T) {
	db, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	// Published after the capture: not counted.
	p, hits := db.Match("dropbear", "2016.73", march2018)
	if p == nil || p.CPE != "dropbear_ssh_project:dropbear_ssh" || len(hits) != 1 || hits[0].CVE.ID != "CVE-2016-7406" || hits[0].Partial || hits[0].DaysPublished != 382 {
		t.Fatalf("dropbear 2016.73: %+v", hits)
	}
	if _, hits := db.Match("Dropbear", "2016.74", march2018); len(hits) != 0 {
		t.Fatalf("fixed version: %v", ids(hits))
	}
	// udhcp names its BusyBox version; 0.9.x is the old stand-alone project.
	if _, hits := db.Match("udhcp", "1.19.4", march2018); len(hits) != 1 || hits[0].CVE.ID != "CVE-2016-2148" {
		t.Fatalf("udhcp 1.19.4: %v", ids(hits))
	}
	if _, hits := db.Match("udhcp", "0.9.8", march2018); len(hits) != 0 {
		t.Fatalf("udhcp 0.9.8: %v", ids(hits))
	}
	// "2.7" may be 2.7.0 (affected) or a later 2.7.x: a partial match.
	if _, hits := db.Match("gsoap", "2.7", march2018); len(hits) != 1 || !hits[0].Partial {
		t.Fatalf("gsoap 2.7: %+v", hits)
	}
	if _, hits := db.Match("gsoap", "2.8.47", march2018); len(hits) != 1 || hits[0].Partial {
		t.Fatalf("gsoap 2.8.47: %+v", hits)
	}
	if _, hits := db.Match("lighttpd", "1.4.29", march2018); hits != nil {
		t.Fatalf("unknown product: %v", ids(hits))
	}
	if _, hits := db.Match("dropbear", "", march2018); hits != nil {
		t.Fatalf("no version: %v", ids(hits))
	}
}

func TestEmbedded(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, hits := db.Match("dropbear", "0.53.1", march2018); len(hits) == 0 {
		t.Fatal("dropbear 0.53.1 should match published CVEs")
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"2016.73", "2016.74", -1}, {"7.4p1", "7.4", 1}, {"1.19.4", "1.19.4", 0}, {"1.2", "1.10", -1}, {"2.7", "2.7.0", 0}} {
		if got := compare(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
