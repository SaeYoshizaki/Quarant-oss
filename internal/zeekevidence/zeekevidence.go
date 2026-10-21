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
	"sync"
	"time"

	"quarant/analyzer"
	"quarant/internal/versionvuln"
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

	CertKeyType    string `json:"cert_key_type"`
	CertKeyLength  int    `json:"cert_key_length"`
	CertSigAlg     string `json:"cert_sig_alg"`
	CertSelfSigned bool   `json:"cert_self_signed"`
	CertExpired    bool   `json:"cert_expired"`
	Established    bool   `json:"established"`

	SSHVersion int    `json:"ssh_version"`
	SSHKex     string `json:"ssh_kex"`
	SSHCipher  string `json:"ssh_cipher"`
	SSHMAC     string `json:"ssh_mac"`
	SSHHostKey string `json:"ssh_host_key"`
	SSHClient  string `json:"ssh_client"`
	SSHServer  string `json:"ssh_server"`

	SNMPVersion          string `json:"snmp_version"`
	SNMPHasCommunity     bool   `json:"snmp_has_community"`
	SNMPDefaultCommunity bool   `json:"snmp_default_community"`
	SNMPAgent            string `json:"snmp_agent"`
	SNMPResponses        int    `json:"snmp_responses"`

	SWHost    string `json:"sw_host"`
	SWType    string `json:"sw_type"`
	SWName    string `json:"sw_name"`
	SWVersion string `json:"sw_version"`
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
	// Zeek names a host's software once per run; a capture split into many
	// files names it once per file.
	seenSoftware := map[string]bool{}
	for _, r := range rows {
		switch r.Kind {
		case "software":
			k := r.SWHost + "|" + r.SWType + "|" + strings.ToLower(r.SWName) + "|" + r.SWVersion
			if seenSoftware[k] {
				continue
			}
			seenSoftware[k] = true
			out = append(out, softwareEvents(r, local)...)
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
		case "ssh":
			out = append(out, sshEvents(r, local)...)
		case "snmp":
			if e, ok := snmpEvent(r, local); ok {
				out = append(out, e)
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

// rowTime is the capture time of the row (microseconds, as Zeek writes).
func rowTime(r Row) time.Time {
	sec, frac := math.Modf(r.TS)
	return time.Unix(int64(sec), int64(math.Round(frac*1e6))*1e3).UTC()
}

func baseEvent(r Row, typ, category string, sev analyzer.Severity, device string) analyzer.Event {
	return analyzer.Event{
		Timestamp:  rowTime(r),
		Type:       typ,
		Severity:   sev,
		RuleID:     "ZEEK_" + typ,
		Category:   category,
		Source:     Source,
		FlowKey:    flowKey(r),
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

// flowKey is Quarant's flow key; SNMP runs over UDP, which Quarant does not
// keep flows for, so it only gets the same shape with a udp prefix.
func flowKey(r Row) string {
	k := analyzer.TCPFlowKey(r.OrigH, r.OrigP, r.RespH, r.RespP)
	if r.Kind == "snmp" {
		return "udp|" + strings.TrimPrefix(k, "tcp|")
	}
	return k
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
	if e, ok := certEvent(r, local); ok {
		out = append(out, e)
	}
	return out
}

// certWeakness names what is weak about the server's leaf certificate under
// NIST SP 800-131A Rev. 2: RSA or DSA keys under 2048 bits and EC keys under
// 224 bits are disallowed, and so is SHA-1 (or MD5) for signature
// generation. The signature of a self-signed certificate is not checked:
// such a certificate is trusted by pinning, not through its signature.
func certWeakness(r Row) []string {
	var out []string
	switch strings.ToLower(r.CertKeyType) {
	case "rsa", "dsa":
		if r.CertKeyLength > 0 && r.CertKeyLength < 2048 {
			out = append(out, fmt.Sprintf("weak_certificate_key key=%s%d", strings.ToLower(r.CertKeyType), r.CertKeyLength))
		}
	case "ecdsa", "ec":
		if r.CertKeyLength > 0 && r.CertKeyLength < 224 {
			out = append(out, fmt.Sprintf("weak_certificate_key key=ecdsa%d", r.CertKeyLength))
		}
	}
	sig := strings.ToLower(r.CertSigAlg)
	if !r.CertSelfSigned && (strings.Contains(sig, "sha1") || strings.Contains(sig, "md5")) {
		out = append(out, "weak_certificate_signature signature="+r.CertSigAlg)
	}
	return out
}

func certEvent(r Row, local analyzer.LocalNetworks) (analyzer.Event, bool) {
	weak := certWeakness(r)
	if len(weak) == 0 {
		return analyzer.Event{}, false
	}
	e := baseEvent(r, "I7_TLS_WEAK_CERTIFICATE_OBSERVED", "I7", analyzer.SeverityWarning, deviceEnd(r, local, true))
	kinds := make([]string, 0, len(weak))
	for _, w := range weak {
		kinds = append(kinds, "risk_kind="+w)
	}
	e.Evidence = strings.Join(kinds, " ") + fmt.Sprintf(" self_signed=%t established=%t", r.CertSelfSigned, r.Established) + suffix(r)
	e.Message = "Server certificate with a weak key or signature (Zeek X.509 parser)."
	e.ObservedFact = "Zeek's X.509 parser saw the server's leaf certificate in the TLS handshake with " + strings.Join(weak, " and ") + "."
	e.Inference = "The channel's server authentication rests on cryptography that NIST SP 800-131A disallows."
	e.Limitation = "Only the leaf certificate is examined; whether the client validated it, pinned it or ignored it is not visible. TLS 1.3 sends certificates encrypted, so they are not seen there."
	if !r.Established {
		e.Limitation += " The handshake was not seen to complete, so the client may have rejected the certificate."
		e.Confidence = "medium"
	}
	return e, true
}

// SSH key exchange methods that RFC 9142 says SHOULD NOT or MUST NOT be
// implemented, and ciphers that RFC 8758 (RC4) or RFC 4253 ("none") rule
// out.
var (
	weakSSHKex = map[string]bool{
		"diffie-hellman-group1-sha1": true, "diffie-hellman-group-exchange-sha1": true, "rsa1024-sha1": true,
	}
	weakSSHKexPrefix = []string{"gss-gex-sha1-", "gss-group1-sha1-", "gss-group14-sha1-"}
	weakSSHCipher    = map[string]string{"arcfour": "rc4", "arcfour128": "rc4", "arcfour256": "rc4", "none": "null"}
)

func sshEvents(r Row, local analyzer.LocalNetworks) []analyzer.Event {
	var out []analyzer.Event
	dev := deviceEnd(r, local, true)
	sw := ""
	if r.SSHServer != "" {
		sw = fmt.Sprintf(" ssh_server=%q", r.SSHServer)
	}
	if r.SSHVersion == 1 {
		e := baseEvent(r, "I7_SSH_WEAK_VERSION_OBSERVED", "I7", analyzer.SeverityWarning, dev)
		e.Evidence = "risk_kind=deprecated_ssh_version ssh_version=1" + sw + suffix(r)
		e.Message = "SSH protocol version 1 in use (Zeek SSH parser)."
		e.ObservedFact = "Zeek's SSH parser saw an SSH session that used protocol version 1."
		e.Inference = "SSH-1 has known design flaws and is outside current best practice."
		e.Limitation = "The payload was not decrypted; what the session carried is not known."
		out = append(out, e)
	}
	var weak []string
	kex := strings.ToLower(r.SSHKex)
	if weakSSHKex[kex] {
		weak = append(weak, "weak_ssh_kex kex="+r.SSHKex)
	} else {
		for _, p := range weakSSHKexPrefix {
			if strings.HasPrefix(kex, p) {
				weak = append(weak, "weak_ssh_kex kex="+r.SSHKex)
				break
			}
		}
	}
	if k, ok := weakSSHCipher[strings.ToLower(r.SSHCipher)]; ok {
		weak = append(weak, k+"_cipher cipher="+r.SSHCipher)
	}
	if len(weak) > 0 {
		e := baseEvent(r, "I7_SSH_WEAK_ALGORITHM_SELECTED", "I7", analyzer.SeverityWarning, dev)
		kinds := make([]string, 0, len(weak))
		for _, w := range weak {
			kinds = append(kinds, "risk_kind="+w)
		}
		e.Evidence = strings.Join(kinds, " ") + sw + suffix(r)
		e.Message = "SSH session negotiated a deprecated algorithm (Zeek SSH parser)."
		e.ObservedFact = "Zeek's SSH parser saw the session negotiate " + strings.Join(weak, " and ") + "."
		e.Inference = "Both ends accept an algorithm that RFC 9142 or RFC 8758 rules out; the server offers it."
		e.Limitation = "The negotiated algorithm is the first one both sides support; stronger ones may also be enabled on the server. The payload was not decrypted."
		out = append(out, e)
	}
	return out
}

// snmpEvent reports SNMP v1/v2c only when an agent answered: a request
// nobody answers (discovery, a scanner) shows nothing about any device. The
// agent is the device; its community travelled in cleartext and was
// accepted.
func snmpEvent(r Row, local analyzer.LocalNetworks) (analyzer.Event, bool) {
	if !r.SNMPHasCommunity || r.SNMPResponses == 0 || r.SNMPAgent == "" || !local.Contains(r.SNMPAgent) {
		return analyzer.Event{}, false
	}
	if r.SNMPDefaultCommunity {
		e := baseEvent(r, "INSECURE_SNMP_DEFAULT_COMMUNITY", "I1", analyzer.SeverityCritical, r.SNMPAgent)
		e.Evidence = fmt.Sprintf("snmp_default_community=*** snmp_version=%s responses=%d", r.SNMPVersion, r.SNMPResponses) + suffix(r)
		e.Message = "SNMP agent answered a well-known default community (Zeek SNMP parser)."
		e.ObservedFact = "An SNMP agent sent GetResponse to a request whose community equals a well-known default (public or private; compared in memory, not stored)."
		e.Inference = "The agent accepts a universal default credential that anyone on the network can use."
		e.Limitation = "Whether the community also allows writes, and whether the user could have changed it, is not known. Only v1/v2c communities are examined."
		e.OWASPTags = []string{"I1", "I9"}
		return e, true
	}
	e := baseEvent(r, "INSECURE_SNMP_COMMUNITY", "I7", analyzer.SeverityCritical, r.SNMPAgent)
	e.Evidence = fmt.Sprintf("snmp_community=*** snmp_version=%s responses=%d", r.SNMPVersion, r.SNMPResponses) + suffix(r)
	e.Message = "SNMP community sent in cleartext and accepted (Zeek SNMP parser)."
	e.ObservedFact = "An SNMP v1/v2c agent answered a request carrying a community, which travels in cleartext."
	e.Inference = "The community works as a password and can be read by anyone on the network path."
	e.Limitation = "The value was not examined; what the community allows is not known."
	return e, true
}

// Where a device names its software to anyone who asks, without
// authentication. Server banners and the DHCP vendor class reach every
// client or the whole network; a User-Agent goes to the device's own
// services and is not counted as disclosure.
var disclosureTypes = map[string]struct {
	what, confidence, note string
}{
	"HTTP::SERVER": {"the Server header of its web server", "medium", "RFC 9110 makes the Server header optional and advises against fine-grained detail."},
	"FTP::SERVER":  {"its FTP greeting", "medium", "FTP does not require a version in the greeting."},
	"DHCP::CLIENT": {"the DHCP vendor class it broadcasts", "medium", "The vendor class (RFC 2132 option 60) is optional."},
	"SSH::SERVER":  {"its SSH banner", "low", "SSH requires a software version field in the banner (RFC 4253 4.2), so naming the software is expected by the protocol."},
}

// Names that come from the UPnP SERVER string ("Linux/2.6 UPnP/1.0
// product/1.0"), whose OS and UPnP version the UPnP Device Architecture
// requires; Zeek takes its first token as the HTTP server.
var upnpMandated = map[string]bool{"linux": true, "unspecified": true}

// plausibleDisclosure leaves out names that come from the UPnP string and
// one-letter names that are parse artefacts ("H.264" read as "H" 264).
func plausibleDisclosure(name string) bool {
	n := strings.ToLower(name)
	return len(n) > 1 && !upnpMandated[n] && !strings.Contains(n, "upnp")
}

var vulnDB = sync.OnceValues(versionvuln.Load)

func softwareEvents(r Row, local analyzer.LocalNetworks) []analyzer.Event {
	if r.SWHost == "" || !local.Contains(r.SWHost) || r.SWName == "" {
		return nil
	}
	var out []analyzer.Event
	sw := fmt.Sprintf("software_type=%s name=%q version=%s", r.SWType, r.SWName, r.SWVersion)
	tail := fmt.Sprintf(" host=%s source=zeek", r.SWHost)
	if d, ok := disclosureTypes[r.SWType]; ok && r.SWVersion != "" && plausibleDisclosure(r.SWName) {
		e := baseEvent(r, "I3_SOFTWARE_VERSION_DISCLOSED", "I3", analyzer.SeverityInfo, r.SWHost)
		e.FlowKey, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort = "", r.SWHost, 0, "", 0
		e.Evidence = sw + tail
		e.Message = "Device names its software version without authentication (Zeek software framework)."
		e.ObservedFact = fmt.Sprintf("The device named %s %s in %s.", r.SWName, r.SWVersion, d.what)
		e.Inference = "Anyone on the network can learn the component version and look up its known vulnerabilities."
		e.Limitation = d.note + " The named version may not be the one running."
		e.Confidence = d.confidence
		e.OWASPTags = []string{"I3"}
		out = append(out, e)
	}
	db, err := vulnDB()
	if err != nil || r.SWVersion == "" {
		return out
	}
	product, hits := db.Match(r.SWName, r.SWVersion, rowTime(r))
	if len(hits) == 0 {
		return out
	}
	var list []string
	kev, partial := 0, true
	for i, h := range hits {
		if h.CVE.KEV {
			kev++
		}
		if !h.Partial {
			partial = false
		}
		if i < 5 {
			list = append(list, fmt.Sprintf("%s(%s,%dd)", h.CVE.ID, strings.ToLower(h.CVE.Severity), h.DaysPublished))
		}
	}
	e := baseEvent(r, "I5_VULNERABLE_VERSION_CANDIDATE", "I5", analyzer.SeverityWarning, r.SWHost)
	e.FlowKey, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort = "", r.SWHost, 0, "", 0
	e.Basis = analyzer.BasisReferenceMatch
	e.Evidence = fmt.Sprintf("%s cpe=%s cve_count=%d kev_count=%d oldest_days=%d cves=%s knowledge=component_cves.json@%s",
		sw, product.CPE, len(hits), kev, maxDays(hits), strings.Join(list, ","), db.Fetched) + tail
	e.Message = "A software version the device names is in the affected range of published CVEs (NVD)."
	e.ObservedFact = fmt.Sprintf("The device named %s %s (%s); %d CVEs published before the capture list this version as affected.", r.SWName, r.SWVersion, r.SWType, len(hits))
	e.Inference = "The component may carry known vulnerabilities that were public, some for a long time, when the traffic was captured."
	e.Limitation = "A candidate, not a finding: the named version may not be the one running, vendors backport fixes without changing the version string, and the affected feature may not be built in. Only CVEs published before the capture are counted."
	e.Confidence = "medium"
	if partial {
		e.Confidence = "low"
		e.Limitation += " The named version has fewer parts than the affected versions, so it may be outside the range."
	}
	if product.Suite {
		e.Confidence = "low"
		e.Limitation += " The product bundles many programs; a CVE may concern one the device does not build in."
	}
	e.OWASPTags = []string{"I5"}
	out = append(out, e)
	return out
}

func maxDays(hits []versionvuln.Hit) int {
	m := 0
	for _, h := range hits {
		if h.DaysPublished > m {
			m = h.DaysPublished
		}
	}
	return m
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

	// Credentials sent to the device by another host are the device's only
	// if the device accepted them; refused or unanswered ones may be
	// guesses (a scanner, a brute force: E9), so they stay low.
	toDevice := dev == r.RespH && local.Contains(r.RespH)
	accepted := r.Status >= 200 && r.Status < 400
	guessNote := " The credential was sent to the device and not seen accepted (no 2xx/3xx answer), so it may be a guess by another host."
	lower := func(e *analyzer.Event) {
		if toDevice && !accepted {
			e.Confidence = "low"
			e.Limitation += guessNote
		}
	}
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
		lower(&e)
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
			lower(&e)
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
