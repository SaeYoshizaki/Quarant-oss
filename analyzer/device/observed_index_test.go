package device

import "testing"

func TestObservedIndexMatch(t *testing.T) {
	d := &DeviceProfile{Paths: map[string]bool{}}
	add := func(v string) {
		d.Paths[v] = true
		d.noteObserved("path", v)
	}
	add("/index.html")
	add("/api/Hue/config")
	add("/philips/hue")
	ix := d.observedIndexFor("path", d.Paths)
	// The earliest value that contains any keyword, and its first keyword
	// in list order.
	if v, k, ok := ix.match([]string{"philips", " HUE "}); !ok || v != "/api/Hue/config" || k != "hue" {
		t.Fatalf("match = %q %q %v", v, k, ok)
	}
	if _, _, ok := ix.match([]string{"sonos", ""}); ok {
		t.Fatal("no value contains sonos")
	}
	// A value added later is found by a keyword that had no match before.
	add("/sonos/status")
	if v, _, ok := d.observedIndexFor("path", d.Paths).match([]string{"sonos"}); !ok || v != "/sonos/status" {
		t.Fatalf("after add: %q %v", v, ok)
	}
}

func TestObservedIndexWithoutNote(t *testing.T) {
	// Maps filled directly (tests, merged profiles) are indexed in sorted
	// order; a replaced map is re-indexed.
	d := &DeviceProfile{Hosts: map[string]bool{"b.example": true, "a.example": true}}
	if v, _, ok := d.observedIndexFor("host", d.Hosts).match([]string{"example"}); !ok || v != "a.example" {
		t.Fatalf("got %q %v", v, ok)
	}
	d.Hosts = map[string]bool{"c.test": true}
	if v, _, ok := d.observedIndexFor("host", d.Hosts).match([]string{"test", "example"}); !ok || v != "c.test" {
		t.Fatalf("re-index: %q %v", v, ok)
	}
}
