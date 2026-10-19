package zeekevidence

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"quarant/analyzer"
)

var local = analyzer.DefaultLocalNetworks()

func row(kind string) Row {
	return Row{TS: 1700000000.25, UID: "Cabc", Kind: kind, OrigH: "192.168.1.10", OrigP: 50000, RespH: "203.0.113.5", RespP: 80}
}

func types(evs []analyzer.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

func TestTLS(t *testing.T) {
	r := row("tls")
	r.RespP = 443
	r.Version = "TLSv10"
	r.Cipher = "TLS_RSA_WITH_RC4_128_SHA"
	evs := Convert([]Row{r}, local)
	if got := strings.Join(types(evs), ","); got != "I7_TLS_WEAK_VERSION_OBSERVED,I7_TLS_WEAK_CIPHER_SELECTED" {
		t.Fatalf("types = %s", got)
	}
	if !strings.Contains(evs[0].Evidence, "risk_kind=deprecated_tls_version tls_version=TLS1.0 selected_or_offered=selected") {
		t.Errorf("version evidence = %s", evs[0].Evidence)
	}
	if !strings.Contains(evs[1].Evidence, "risk_kind=rc4_cipher") {
		t.Errorf("cipher evidence = %s", evs[1].Evidence)
	}

	// No ServerHello: the client's highest offer decides, with lower confidence.
	r = row("tls")
	r.ClientVersions = "max=TLSv11"
	evs = Convert([]Row{r}, local)
	if len(evs) != 1 || !strings.Contains(evs[0].Evidence, "tls_version=TLS1.1 selected_or_offered=offered") || evs[0].Confidence != "medium" {
		t.Fatalf("offered: %+v", evs)
	}
	r.ClientVersions = "TLSv13,TLSv12,TLSv11"
	if evs := Convert([]Row{r}, local); len(evs) != 0 {
		t.Fatalf("a client offering TLS 1.3 is not evidence: %v", types(evs))
	}
	// CBC suites alone are not violation evidence (E4).
	r = row("tls")
	r.Version = "TLSv12"
	r.Cipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	if evs := Convert([]Row{r}, local); len(evs) != 0 {
		t.Fatalf("CBC: %v", types(evs))
	}
}

func TestHTTPAuthorization(t *testing.T) {
	cases := []struct {
		scheme, want string
	}{
		{"basic", "Authorization: Basic ***"},
		{"Bearer", "Authorization: Bearer ***"},
		{"none", "Authorization: ***"},
		// An older log took the first word of a header without a scheme,
		// i.e. the value; it must not reach the evidence.
		{"d41d8cd98f00b204", "Authorization: ***"},
		{"aws4-hmac-sha256", ""},
		{"digest", ""},
	}
	for _, c := range cases {
		r := row("http")
		r.AuthScheme = c.scheme
		evs := Convert([]Row{r}, local)
		if c.want == "" {
			if len(evs) != 0 {
				t.Errorf("%s: signature scheme reported: %v", c.scheme, types(evs))
			}
			continue
		}
		if len(evs) != 1 || evs[0].Type != "INSECURE_HTTP_AUTH" || !strings.HasPrefix(evs[0].Evidence, c.want+" src=") {
			t.Errorf("%s: %+v", c.scheme, evs)
		}
		if strings.Contains(evs[0].Evidence, "d41d8") {
			t.Errorf("value leaked: %s", evs[0].Evidence)
		}
	}
}

func TestHTTPNames(t *testing.T) {
	r := row("http")
	r.ReqHeaders = []string{"host", "cookie", "x-auth-token", "www-authenticate", "sid"}
	r.URIParams = []string{"access_token", "model", "authuser", "%26token"}
	r.ReqBodyKeys = []string{"password", "gkefmd6drkfvxpwdrrtcnq"}
	r.RespBodyKeys = []string{"session_id"}
	got := map[string]string{}
	for _, e := range Convert([]Row{r}, local) {
		got[strings.SplitN(e.Evidence, " src=", 2)[0]] = e.Type
		if e.Type != "INSECURE_HTTP_COOKIE" && e.Confidence != "low" {
			t.Errorf("name-only %s has confidence %s", e.Type, e.Confidence)
		}
	}
	want := map[string]string{
		"Cookie: ***":             "INSECURE_HTTP_COOKIE",
		"header x-auth-token=***": "INSECURE_HTTP_TOKEN",
		"access_token=***":        "I3_AUTH_TOKEN_IN_URL",
		"authuser=***":            "I3_AUTH_TOKEN_IN_URL",
		"body password=***":       "INSECURE_HTTP_BODY_SECRET",
		"response session_id=***": "INSECURE_HTTP_RESPONSE_SECRET",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("missing %q -> %s (got %v)", k, v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("extra events: %v", got)
	}
}

func TestMedia(t *testing.T) {
	r := row("http")
	r.Method = "POST"
	r.OrigMIME = []string{"text/plain", "image/jpeg", "image/jpeg"}
	r.ReqBodyLen = 2048
	evs := Convert([]Row{r}, local)
	if len(evs) != 1 || evs[0].Type != "I6_MEDIA_UPLOAD_CLEARTEXT" || !strings.Contains(evs[0].Evidence, "content_magic=image/jpeg ") || evs[0].Confidence != "low" {
		t.Fatalf("media: %+v", evs)
	}
	// Inside the home network: not an upload to a remote service.
	r.RespH = "192.168.1.20"
	if evs := Convert([]Row{r}, local); len(evs) != 0 {
		t.Fatalf("LAN media: %v", types(evs))
	}
}

func TestCredentialsAndDevice(t *testing.T) {
	m := row("mqtt")
	m.RespP = 1883
	m.HasPassword = true
	f := row("ftp")
	f.RespP = 21
	f.HasPassword = true
	anon := f
	anon.Anonymous = true
	// A phone logging in to a camera in the same network: the camera's
	// password is the one exposed.
	lan := row("http")
	lan.RespH = "192.168.1.20"
	lan.AuthScheme = "basic"
	evs := Convert([]Row{m, f, anon, lan}, local)
	if got := strings.Join(types(evs), ","); got != "INSECURE_MQTT_CREDENTIALS,INSECURE_FTP_CREDENTIALS,INSECURE_HTTP_AUTH" {
		t.Fatalf("types = %s", got)
	}
	if evs[0].DeviceKey != "192.168.1.10" || evs[2].DeviceKey != "192.168.1.20" {
		t.Errorf("devices: %s %s", evs[0].DeviceKey, evs[2].DeviceKey)
	}
}

func TestEventContract(t *testing.T) {
	r := row("http")
	r.AuthScheme = "basic"
	r.ReqHeaders = []string{"cookie", "x-api-key"}
	r.URIParams = []string{"token"}
	r.ReqBodyKeys = []string{"pwd"}
	r.RespBodyKeys = []string{"secret"}
	r.OrigMIME = []string{"video/mp4"}
	tl := row("tls")
	tl.Version = "SSLv3"
	tl.Cipher = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
	m := row("mqtt")
	m.HasPassword = true
	evs := Convert([]Row{r, tl, m}, local)
	if len(evs) < 9 {
		t.Fatalf("got %d events", len(evs))
	}
	for _, e := range evs {
		if e.Basis != analyzer.BasisObserved || e.ObservedFact == "" || e.Inference == "" || e.Limitation == "" || e.Confidence == "" {
			t.Errorf("%s misses a required field: %+v", e.Type, e)
		}
		if e.Source != Source || !strings.Contains(e.Evidence, "source=zeek uid=Cabc") {
			t.Errorf("%s: source not recorded", e.Type)
		}
		if e.FlowKey != analyzer.TCPFlowKey(e.SrcIP, e.SrcPort, e.DstIP, e.DstPort) {
			t.Errorf("%s: flow key %s", e.Type, e.FlowKey)
		}
		if e.Timestamp.UnixMicro() != 1700000000250000 {
			t.Errorf("%s: capture time not kept: %v", e.Type, e.Timestamp)
		}
	}
}

// Runs Zeek on the synthetic capture when Zeek is installed.
func TestRunZeekSynthetic(t *testing.T) {
	if _, err := exec.LookPath("zeek"); err != nil {
		t.Skip("zeek not installed")
	}
	work := t.TempDir()
	log, err := RunZeek(context.Background(), "", filepath.Join("..", "..", "examples", "pcap", "synthetic-home.pcap"), work)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := ReadRows(f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range Convert(rows, local) {
		got[e.Type] = true
	}
	for _, want := range []string{"I7_TLS_WEAK_VERSION_OBSERVED", "INSECURE_HTTP_AUTH", "INSECURE_MQTT_CREDENTIALS"} {
		if !got[want] {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
	// Only the evidence log is written; Zeek's own logs (URLs, cookies)
	// are not.
	for _, name := range []string{"http.log", "ssl.log", "conn.log", "ftp.log"} {
		if _, err := os.Stat(filepath.Join(work, name)); err == nil {
			t.Errorf("%s was written", name)
		}
	}
}
