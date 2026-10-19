// Package zeekevidence turns Zeek's parse of a capture into Quarant events
// for the ETSI EN 303 645 provisions. Zeek does the protocol parsing
// (evidence.zeek writes names and shapes, never values); this package
// decides what each row is evidence of and attaches basis, observed fact,
// inference and limitation like the built-in rules do.
//
// The event types are the ones the built-in rules use, so
// docs/assessment/evidence-map.json and the scripts that read it apply to
// both. Every event carries source=zeek.
package zeekevidence

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"quarant/analyzer"
)

//go:embed evidence.zeek
var Script []byte

// LogName is the file evidence.zeek writes.
const LogName = "quarant_evidence.log"

const Source = "zeek"

// Row is one line of quarant_evidence.log (Zeek JSON).
type Row struct {
	TS             float64  `json:"ts"`
	UID            string   `json:"uid"`
	Kind           string   `json:"kind"`
	OrigMAC        string   `json:"orig_mac"`
	RespMAC        string   `json:"resp_mac"`
	OrigH          string   `json:"orig_h"`
	OrigP          uint16   `json:"orig_p"`
	RespH          string   `json:"resp_h"`
	RespP          uint16   `json:"resp_p"`
	Version        string   `json:"version"`
	Cipher         string   `json:"cipher"`
	ClientVersions string   `json:"client_versions"`
	SNI            string   `json:"sni"`
	Method         string   `json:"method"`
	Host           string   `json:"host"`
	Status         int      `json:"status"`
	ReqHeaders     []string `json:"req_headers"`
	AuthScheme     string   `json:"auth_scheme"`
	URIParams      []string `json:"uri_params"`
	ReqBodyKeys    []string `json:"req_body_keys"`
	RespBodyKeys   []string `json:"resp_body_keys"`
	OrigMIME       []string `json:"orig_mime"`
	ReqBodyLen     int      `json:"req_body_len"`
	HasUsername    bool     `json:"has_username"`
	HasPassword    bool     `json:"has_password"`
	Anonymous      bool     `json:"anonymous"`
}

// RunZeek runs Zeek with evidence.zeek over pcap inside workDir and returns
// the path of the evidence log. zeekBin defaults to "zeek" on PATH.
func RunZeek(ctx context.Context, zeekBin, pcap, workDir string) (string, error) {
	if zeekBin == "" {
		zeekBin = "zeek"
	}
	abs, err := filepath.Abs(pcap)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", err
	}
	script := filepath.Join(workDir, "quarant-evidence.zeek")
	if err := os.WriteFile(script, Script, 0o644); err != nil {
		return "", err
	}
	// -C: captures often carry offloaded (wrong) checksums.
	cmd := exec.CommandContext(ctx, zeekBin, "-C", "-r", abs, script, "LogAscii::use_json=T")
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("zeek: %w: %s", err, strings.TrimSpace(string(out)))
	}
	log := filepath.Join(workDir, LogName)
	if _, err := os.Stat(log); os.IsNotExist(err) {
		// Nothing to report: no TLS, HTTP, MQTT or FTP in the capture.
		if err := os.WriteFile(log, nil, 0o644); err != nil {
			return "", err
		}
	}
	return log, nil
}

// ReadRows parses quarant_evidence.log.
func ReadRows(r io.Reader) ([]Row, error) {
	var rows []Row
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := strings.TrimSpace(sc.Text())
		if b == "" || strings.HasPrefix(b, "#") {
			continue
		}
		var row Row
		if err := json.Unmarshal([]byte(b), &row); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		rows = append(rows, row)
	}
	return rows, sc.Err()
}

// Same definitions as scripts/accuracy/compare_misses.py, so that the Zeek
// path and the ground truth of E11-E14 agree on what counts.
var (
	oldTLS = map[string]string{"SSLv2": "SSL2.0", "SSLv3": "SSL3.0", "TLSv10": "TLS1.0", "TLSv11": "TLS1.1"}
	// Order of strength, for the client's highest offered version.
	tlsOrder     = []string{"SSLv2", "SSLv3", "TLSv10", "TLSv11", "TLSv12", "TLSv13"}
	brokenCipher = []struct {
		re   *regexp.Regexp
		kind string
	}{
		{regexp.MustCompile(`_anon_`), "anonymous"},
		{regexp.MustCompile(`_NULL_`), "null"},
		{regexp.MustCompile(`EXPORT|DES40`), "export"},
		{regexp.MustCompile(`RC4`), "rc4"},
		{regexp.MustCompile(`3DES`), "3des"},
		{regexp.MustCompile(`_DES_`), "des"},
		{regexp.MustCompile(`_MD5`), "md5"},
	}
	// A secret word at the start or end of the name or next to a separator
	// ("password", "x-auth-token", "accesstoken"). The ground truth matched
	// anywhere, which also took random strings ("...xpwdrr...", a value
	// that Zeek's key pattern took for a name).
	secretName = regexp.MustCompile(`(^|[_\-.\[])(pass|pwd|token|secret|api[_\-]?key|apikey|auth|session|sid|sign)|(pass|passwd|password|pwd|token|secret|apikey|accesskey|secretkey|privatekey|auth|session|sid|sign|signature)($|[_\-.\]])`)
	// Header names that match secretName but carry no secret by definition.
	// SID is the UPnP GENA subscription identifier.
	benignHeaders = map[string]bool{"www-authenticate": true, "proxy-authenticate": true, "authentication-info": true, "sid": true}
	// Per-request signatures: the header cannot be replayed for another
	// request, so it is not a reusable credential in cleartext.
	signatureSchemes = map[string]bool{"aws4-hmac-sha256": true, "aws": true, "oss": true, "digest": true}
	knownSchemes     = map[string]string{"basic": "Basic", "bearer": "Bearer", "token": "Token", "hmac": "HMAC", "jwt": "JWT", "key": "Key", "apikey": "ApiKey", "otp": "OTP", "negotiate": "Negotiate", "ntlm": "NTLM"}
	// URL parameter names; anything else may be a bare value.
	paramName = regexp.MustCompile(`^[a-z0-9_\-.\[\]]{1,40}$`)
)

// Convert turns rows into events. local decides which end is a device.
func Convert(rows []Row, local analyzer.LocalNetworks) []analyzer.Event {
	var out []analyzer.Event
	for _, r := range rows {
		switch r.Kind {
		case "tls":
			out = append(out, tlsEvents(r, local)...)
		case "http":
			out = append(out, httpEvents(r, local)...)
		case "mqtt":
			if r.HasPassword {
				out = append(out, credentialEvent(r, local, "INSECURE_MQTT_CREDENTIALS", "mqtt_password=***",
					"An MQTT CONNECT with a non-empty password field was observed in cleartext (Zeek MQTT parser).",
					"The broker password can be read by anyone on the network path."))
			}
		case "ftp":
			if r.HasPassword && !r.Anonymous {
				out = append(out, credentialEvent(r, local, "INSECURE_FTP_CREDENTIALS", "ftp_user=*** ftp_password=***",
					"The client sent FTP USER and a non-empty PASS in cleartext (Zeek FTP parser); the user was not anonymous.",
					"The password can be read by anyone on the network path."))
			}
		}
	}
	return out
}

// deviceEnd picks the end whose evidence it is. A finding about a client's
// own behaviour (what it offered, what it sent) belongs to the client when
// that is local; a finding about a service (what it chose, what it accepts)
// belongs to the server when that is local. Otherwise the local end is used.
func deviceEnd(r Row, local analyzer.LocalNetworks, serverSide bool) string {
	o, s := local.Contains(r.OrigH), local.Contains(r.RespH)
	switch {
	case o && s:
		if serverSide {
			return r.RespH
		}
		return r.OrigH
	case s:
		return r.RespH
	default:
		return r.OrigH
	}
}

func baseEvent(r Row, typ, category string, sev analyzer.Severity, device string) analyzer.Event {
	sec, frac := math.Modf(r.TS)
	return analyzer.Event{
		Timestamp:  time.Unix(int64(sec), int64(math.Round(frac*1e6))*1e3).UTC(),
		Type:       typ,
		Severity:   sev,
		RuleID:     "ZEEK_" + typ,
		Category:   category,
		Source:     Source,
		FlowKey:    analyzer.TCPFlowKey(r.OrigH, r.OrigP, r.RespH, r.RespP),
		Basis:      analyzer.BasisObserved,
		DeviceKey:  device,
		SrcIP:      r.OrigH,
		SrcPort:    r.OrigP,
		DstIP:      r.RespH,
		DstPort:    r.RespP,
		OWASPTags:  []string{"I7"},
		Confidence: "high",
	}
}

func peer(r Row) string {
	if r.SNI != "" {
		return r.SNI
	}
	if r.Host != "" {
		return r.Host
	}
	return r.RespH
}

func suffix(r Row) string {
	return fmt.Sprintf(" src=%s:%d dst=%s:%d peer=%s source=zeek uid=%s", r.OrigH, r.OrigP, r.RespH, r.RespP, peer(r), r.UID)
}

func tlsEvents(r Row, local analyzer.LocalNetworks) []analyzer.Event {
	var out []analyzer.Event
	ver, basis := r.Version, "selected"
	if ver == "" {
		ver, basis = clientMax(r.ClientVersions), "offered"
	}
	if name, ok := oldTLS[ver]; ok {
		// A selected version is the server's choice; without a ServerHello
		// only the client's highest offer is known.
		e := baseEvent(r, "I7_TLS_WEAK_VERSION_OBSERVED", "I7", analyzer.SeverityWarning, deviceEnd(r, local, basis == "selected"))
		e.Evidence = fmt.Sprintf("risk_kind=deprecated_tls_version tls_version=%s selected_or_offered=%s observed_value=%s", name, basis, name) + suffix(r)
		e.Message = "Deprecated TLS version observed (Zeek SSL parser)."
		e.ObservedFact = fmt.Sprintf("Zeek's SSL parser saw a TLS handshake whose %s version was %s.", map[string]string{"selected": "selected", "offered": "highest offered"}[basis], name)
		e.Inference = "The channel uses a protocol version outside current best practice."
		e.Limitation = "The payload was not decrypted. Which side insisted on the old version, and what the channel carries, are not known from metadata alone."
		if basis == "offered" {
			e.Limitation = "No ServerHello was seen, so the version actually used is unknown; only the client's highest offer is known. The payload was not decrypted."
			e.Confidence = "medium"
		}
		out = append(out, e)
	}
	if r.Cipher != "" {
		for _, b := range brokenCipher {
			if !b.re.MatchString(r.Cipher) {
				continue
			}
			e := baseEvent(r, "I7_TLS_WEAK_CIPHER_SELECTED", "I7", analyzer.SeverityWarning, deviceEnd(r, local, true))
			e.Evidence = fmt.Sprintf("risk_kind=%s_cipher cipher_suite_name=%s selected_or_offered=selected observed_value=%s", b.kind, r.Cipher, r.Cipher) + suffix(r)
			e.Message = "Broken TLS cipher suite selected (Zeek SSL parser)."
			e.ObservedFact = fmt.Sprintf("Zeek's SSL parser saw the server select %s.", r.Cipher)
			e.Inference = "The channel is protected by a cipher suite with known breaks."
			e.Limitation = "The payload was not decrypted. Whether stronger suites were available to either side is not known from one handshake."
			out = append(out, e)
			break
		}
	}
	return out
}

func clientMax(cv string) string {
	best := -1
	for _, v := range strings.Split(strings.TrimPrefix(cv, "max="), ",") {
		for i, o := range tlsOrder {
			if v == o && i > best {
				best = i
			}
		}
	}
	if best < 0 {
		return ""
	}
	return tlsOrder[best]
}

func httpEvents(r Row, local analyzer.LocalNetworks) []analyzer.Event {
	var out []analyzer.Event
	dev := deviceEnd(r, local, true)
	nameLimit := "Only the name was examined (Zeek does not log values here); the value may be empty, public, a per-request signature or already protected."

	if s := strings.ToLower(r.AuthScheme); s != "" && !signatureSchemes[s] {
		e := baseEvent(r, "INSECURE_HTTP_AUTH", "I7", analyzer.SeverityCritical, dev)
		// Only a known scheme name is written: an older log (gt.zeek) took
		// the first word of the header, which is the value itself when the
		// header has no scheme.
		if name, ok := knownSchemes[s]; ok {
			e.Evidence = fmt.Sprintf("Authorization: %s ***", name)
		} else {
			s = "none"
			e.Evidence = "Authorization: ***"
		}
		e.Evidence += suffix(r)
		e.Message = "Authorization header sent over plaintext HTTP (Zeek HTTP parser)."
		e.ObservedFact = "An HTTP request in cleartext carried an Authorization header" + schemeNote(s) + "."
		e.Inference = "A reusable credential or token can be read by anyone on the network path."
		e.Limitation = "The value was not examined. Whether the login succeeded, and whether the credential is default or shared, is not known."
		out = append(out, e)
	}
	for _, h := range sorted(r.ReqHeaders) {
		switch {
		case h == "cookie":
			e := baseEvent(r, "INSECURE_HTTP_COOKIE", "I7", analyzer.SeverityCritical, dev)
			e.Evidence = "Cookie: ***" + suffix(r)
			e.Message = "Cookie header sent over plaintext HTTP (Zeek HTTP parser)."
			e.ObservedFact = "An HTTP request in cleartext carried a Cookie header."
			e.Inference = "Session state may be readable by anyone on the network path."
			e.Limitation = "The cookie was not examined; it may not carry authentication."
			e.Confidence = "medium"
			out = append(out, e)
		case h != "authorization" && !benignHeaders[h] && secretName.MatchString(h):
			e := baseEvent(r, "INSECURE_HTTP_TOKEN", "I7", analyzer.SeverityCritical, dev)
			e.Evidence = fmt.Sprintf("header %s=***", h) + suffix(r)
			e.Message = "Header named like a secret sent over plaintext HTTP (Zeek HTTP parser)."
			e.ObservedFact = fmt.Sprintf("An HTTP request in cleartext carried a header named %q.", h)
			e.Inference = "A token or key may be readable by anyone on the network path."
			e.Limitation = nameLimit
			e.Confidence = "low"
			out = append(out, e)
		}
	}
	for _, k := range sorted(r.URIParams) {
		if !paramName.MatchString(k) || !secretName.MatchString(k) {
			continue
		}
		e := baseEvent(r, "I3_AUTH_TOKEN_IN_URL", "I3", analyzer.SeverityHigh, dev)
		e.Evidence = k + "=***" + suffix(r)
		e.Message = "URL parameter named like a secret sent over plaintext HTTP (Zeek HTTP parser)."
		e.ObservedFact = fmt.Sprintf("An HTTP request in cleartext had a URL parameter named %q.", k)
		e.Inference = "A token or key may be readable on the network path and in server and proxy logs."
		e.Limitation = nameLimit
		e.Confidence = "low"
		e.OWASPTags = []string{"I3", "I7"}
		out = append(out, e)
	}
	for _, k := range secretKeys(r.ReqBodyKeys) {
		e := baseEvent(r, "INSECURE_HTTP_BODY_SECRET", "I7", analyzer.SeverityCritical, dev)
		e.Evidence = "body " + k + "=***" + suffix(r)
		e.Message = "Request body field named like a secret sent over plaintext HTTP (Zeek HTTP parser)."
		e.ObservedFact = fmt.Sprintf("A cleartext HTTP request body had a field named %q.", k)
		e.Inference = "A credential or key may be readable by anyone on the network path."
		e.Limitation = nameLimit
		e.Confidence = "low"
		out = append(out, e)
	}
	for _, k := range secretKeys(r.RespBodyKeys) {
		e := baseEvent(r, "INSECURE_HTTP_RESPONSE_SECRET", "I7", analyzer.SeverityCritical, dev)
		e.Evidence = "response " + k + "=***" + suffix(r)
		e.Message = "Response body field named like a secret sent over plaintext HTTP (Zeek HTTP parser)."
		e.ObservedFact = fmt.Sprintf("A cleartext HTTP response body had a field named %q.", k)
		e.Inference = "A credential or key given to the client may be readable by anyone on the network path."
		e.Limitation = nameLimit
		e.Confidence = "low"
		out = append(out, e)
	}
	if m := mediaTypes(r.OrigMIME); len(m) > 0 && local.Contains(r.OrigH) && !local.Contains(r.RespH) {
		e := baseEvent(r, "I6_MEDIA_UPLOAD_CLEARTEXT", "I6", analyzer.SeverityHigh, r.OrigH)
		e.Evidence = fmt.Sprintf("method=%s host=%s content_magic=%s content_length=%d", r.Method, peer(r), strings.Join(m, ","), r.ReqBodyLen) + suffix(r)
		e.Message = "Media uploaded to a remote service over plaintext HTTP (Zeek HTTP parser)."
		e.ObservedFact = "Zeek's content sniffing recognised image, video or audio in a cleartext HTTP request body sent to a non-local address."
		e.Inference = "Camera snapshots, recordings or voice clips may be readable by anyone on the network path."
		e.Limitation = "The content is not inspected or stored; whether it shows people or the home, and whether it is encrypted inside the file, is not known. Zeek's sniffing matches the first bytes only and can take a short body for media (O1: a 720-byte POST taken for audio)."
		// Low: on its own this is not evidence (D25); it counts when
		// Quarant's own check agrees.
		e.Confidence = "low"
		e.OWASPTags = []string{"I6", "I7"}
		out = append(out, e)
	}
	return out
}

func credentialEvent(r Row, local analyzer.LocalNetworks, typ, evidence, fact, inference string) analyzer.Event {
	e := baseEvent(r, typ, "I7", analyzer.SeverityCritical, deviceEnd(r, local, true))
	e.Evidence = evidence + suffix(r)
	e.Message = "Login credentials sent in cleartext (Zeek parser)."
	e.ObservedFact = fact
	e.Inference = inference
	e.Limitation = "The value was not examined. Whether the login succeeded, and whether the password is default or shared, is not known."
	return e
}

func schemeNote(s string) string {
	if s == "none" {
		return " without a scheme"
	}
	return " with scheme " + s
}

func mediaTypes(mimes []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range mimes {
		top := strings.SplitN(m, "/", 2)[0]
		if (top == "image" || top == "video" || top == "audio") && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// secretKeys keeps body key names that look like names and are named like
// a secret, sorted.
func secretKeys(keys []string) []string {
	var out []string
	for _, k := range sorted(keys) {
		if paramName.MatchString(k) && secretName.MatchString(k) {
			out = append(out, k)
		}
	}
	return out
}

func sorted(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}
