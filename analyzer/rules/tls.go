package rules

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

type TLSClientHelloInfo struct {
	RecordVersion uint16
	ClientVersion uint16
	SNI           string

	CipherSuites      []uint16
	Extensions        []uint16
	SupportedGroups   []uint16
	SupportedVersions []uint16
	ECPointFormats    []uint8
}

type TLSCertificateInfo struct {
	Subject    string
	Issuer     string
	SANs       []string
	SelfSigned bool
	NotBefore  time.Time
	NotAfter   time.Time
}

type TLSServerInfo struct {
	ServerVersion   uint16
	SelectedVersion uint16
	SelectedCipher  uint16

	Cert *TLSCertificateInfo
}

type TLSRiskClassification struct {
	RiskKind          string
	Severity          Severity
	Reason            string
	ObservedValue     string
	SelectedOrOffered string
}

func DetectTLSServerHello(data []byte) (*TLSServerInfo, bool) {
	for off := 0; off+5 <= len(data); off++ {
		if data[off] != 22 {
			continue
		}

		recVer := binary.BigEndian.Uint16(data[off+1 : off+3])
		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if recLen <= 0 || off+5+recLen > len(data) {
			continue
		}

		rec := data[off+5 : off+5+recLen]
		if len(rec) < 4 {
			continue
		}

		hsType := rec[0]
		if hsType != 2 {
			continue
		}

		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		if hsLen <= 0 || 4+hsLen > len(rec) {
			continue
		}

		sh := rec[4 : 4+hsLen]
		if len(sh) < 2+32+1 {
			continue
		}

		info := &TLSServerInfo{
			ServerVersion: binary.BigEndian.Uint16(sh[0:2]),
			Cert:          nil,
		}

		i := 2 + 32

		sidLen := int(sh[i])
		i++
		if i+sidLen > len(sh) {
			continue
		}
		i += sidLen

		if i+2 > len(sh) {
			continue
		}
		info.SelectedCipher = binary.BigEndian.Uint16(sh[i : i+2])
		i += 2

		if i+1 > len(sh) {
			continue
		}
		compressionLen := 1
		i += compressionLen

		if i < len(sh) {
			if i+2 > len(sh) {
				continue
			}
			extLen := int(binary.BigEndian.Uint16(sh[i : i+2]))
			i += 2
			if extLen < 0 || i+extLen > len(sh) {
				continue
			}
			parseServerHelloExtensions(sh[i:i+extLen], info)
		}

		if info.ServerVersion == 0 {
			info.ServerVersion = recVer
		}

		if cert, ok := DetectTLSCertificate(data); ok {
			info.Cert = cert
		}

		return info, true
	}

	return nil, false
}

func parseServerHelloExtensions(exts []byte, info *TLSServerInfo) {
	if info == nil {
		return
	}
	for j := 0; j+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[j : j+2])
		l := int(binary.BigEndian.Uint16(exts[j+2 : j+4]))
		j += 4
		if l < 0 || j+l > len(exts) {
			return
		}
		body := exts[j : j+l]
		j += l

		if typ != 43 {
			continue
		}
		if len(body) != 2 {
			continue
		}
		info.SelectedVersion = binary.BigEndian.Uint16(body)
	}
}

func DetectTLSCertificate(data []byte) (*TLSCertificateInfo, bool) {
	for off := 0; off+5 <= len(data); off++ {
		if data[off] != 22 {
			continue
		}

		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if recLen <= 0 || off+5+recLen > len(data) {
			continue
		}

		rec := data[off+5 : off+5+recLen]
		if len(rec) < 4 {
			continue
		}

		hsType := rec[0]
		if hsType != 11 {
			continue
		}

		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		if hsLen <= 0 || 4+hsLen > len(rec) {
			continue
		}

		body := rec[4 : 4+hsLen]
		if len(body) < 3 {
			continue
		}

		certListLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
		if certListLen <= 0 || 3+certListLen > len(body) {
			continue
		}

		certs := body[3 : 3+certListLen]
		if len(certs) < 3 {
			continue
		}

		certLen := int(certs[0])<<16 | int(certs[1])<<8 | int(certs[2])
		if certLen <= 0 || 3+certLen > len(certs) {
			continue
		}

		certBytes := certs[3 : 3+certLen]

		parsed, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		info := &TLSCertificateInfo{
			Subject:    parsed.Subject.CommonName,
			Issuer:     parsed.Issuer.CommonName,
			SANs:       append([]string(nil), parsed.DNSNames...),
			SelfSigned: parsed.Subject.String() == parsed.Issuer.String(),
			NotBefore:  parsed.NotBefore,
			NotAfter:   parsed.NotAfter,
		}

		return info, true
	}

	return nil, false
}

func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && ((v>>8)&0xff) == (v&0xff)
}

func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		out = append(out, strconv.Itoa(int(v)))
	}
	return strings.Join(out, "-")
}

func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, strconv.Itoa(int(v)))
	}
	return strings.Join(out, "-")
}

func BuildJA3String(info TLSClientHelloInfo) string {
	return strings.Join([]string{
		strconv.Itoa(int(info.ClientVersion)),
		joinUint16(info.CipherSuites),
		joinUint16(info.Extensions),
		joinUint16(info.SupportedGroups),
		joinUint8(info.ECPointFormats),
	}, ",")
}

func BuildJA3Hash(info TLSClientHelloInfo) string {
	s := BuildJA3String(info)
	if s == "" {
		return ""
	}
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TLSVersionName(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL3.0"
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return "0x" + strings.ToUpper(strconv.FormatUint(uint64(version), 16))
	}
}

func ObservedTLSVersion(ctx *Context) uint16 {
	if ctx == nil {
		return 0
	}
	// Once the ServerHello is seen it decides: without a supported_versions
	// extension its legacy version is the negotiated one (RFC 8446 4.1.3),
	// even when the client offered TLS 1.3 in its own extension.
	if v := ServerNegotiatedTLSVersion(ctx.TLSServerInfo); v != 0 {
		return v
	}
	return ClientMaxTLSVersion(ctx.TLSInfo)
}

// ServerNegotiatedTLSVersion is the version the ServerHello selected, or 0
// when no ServerHello was seen.
func ServerNegotiatedTLSVersion(s *TLSServerInfo) uint16 {
	if s == nil {
		return 0
	}
	if s.SelectedVersion != 0 {
		return s.SelectedVersion
	}
	return s.ServerVersion
}

// ClientMaxTLSVersion is the highest version the ClientHello offered.
func ClientMaxTLSVersion(c *TLSClientHelloInfo) uint16 {
	if c == nil {
		return 0
	}
	if len(c.SupportedVersions) > 0 {
		return strongestTLSVersion(c.SupportedVersions)
	}
	return c.ClientVersion
}

// ServerChoseWeakerTLS reports whether the server selected a deprecated
// version although the client offered a newer one: the weak version is then
// the server's choice, not the client's limit.
func ServerChoseWeakerTLS(c *TLSClientHelloInfo, s *TLSServerInfo) bool {
	selected := ServerNegotiatedTLSVersion(s)
	return IsWeakTLSVersion(selected) && ClientMaxTLSVersion(c) > selected
}

func strongestTLSVersion(versions []uint16) uint16 {
	var strongest uint16
	for _, version := range versions {
		if isGREASE(version) {
			continue
		}
		if version > strongest {
			strongest = version
		}
	}
	return strongest
}

func TLSVersionNames(versions []uint16) string {
	if len(versions) == 0 {
		return ""
	}
	out := make([]string, 0, len(versions))
	seen := map[uint16]struct{}{}
	for _, version := range versions {
		if _, ok := seen[version]; ok {
			continue
		}
		seen[version] = struct{}{}
		out = append(out, TLSVersionName(version))
	}
	return strings.Join(out, ",")
}

func TLSCipherSuiteName(id uint16) string {
	if name, ok := tlsCipherSuiteNames[id]; ok {
		return name
	}
	// crypto/tls knows the IANA names of every suite it implements,
	// including the insecure ones; it returns "0x...." for anything else.
	if name := tls.CipherSuiteName(id); !strings.HasPrefix(name, "0x") {
		return name
	}
	return "0x" + strings.ToUpper(strconv.FormatUint(uint64(id), 16))
}

// IsWeakTLSVersion: SSL 3.0 (RFC 7568), TLS 1.0 and 1.1 (RFC 8996).
func IsWeakTLSVersion(version uint16) bool {
	return version == 0x0300 || version == 0x0301 || version == 0x0302
}

func ClassifyTLSVersion(version uint16, selectedOrOffered string) (TLSRiskClassification, bool) {
	if !IsWeakTLSVersion(version) {
		return TLSRiskClassification{}, false
	}
	return TLSRiskClassification{
		RiskKind:          "deprecated_tls_version",
		Severity:          SeverityWarning,
		Reason:            "deprecated TLS version was observed in passive handshake metadata",
		ObservedValue:     TLSVersionName(version),
		SelectedOrOffered: selectedOrOffered,
	}, true
}

func ClassifyTLSCipherSuite(id uint16, selectedOrOffered string) (TLSRiskClassification, bool) {
	name := TLSCipherSuiteName(id)
	switch id {
	case 0x0000, 0x0001, 0x0002:
		return TLSRiskClassification{RiskKind: "null_cipher", Severity: SeverityHigh, Reason: "NULL encryption or authentication was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case 0x0003, 0x0008, 0x0011, 0x0017, 0x0019:
		return TLSRiskClassification{RiskKind: "export_cipher", Severity: SeverityHigh, Reason: "EXPORT-grade cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case 0x0004, 0x0005, 0x0018:
		return TLSRiskClassification{RiskKind: "rc4_cipher", Severity: SeverityWarning, Reason: "RC4-based cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case 0x0009, 0x001A:
		return TLSRiskClassification{RiskKind: "des_cipher", Severity: SeverityWarning, Reason: "single-DES cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case 0x000A, 0x001B, 0xC012:
		return TLSRiskClassification{RiskKind: "3des_cipher", Severity: SeverityWarning, Reason: "3DES-based cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case 0x002F, 0x0035, 0x003C, 0x003D, 0xC009, 0xC00A, 0xC013, 0xC014:
		return TLSRiskClassification{RiskKind: "cbc_cipher", Severity: SeverityLow, Reason: "CBC-mode TLS cipher suite was observed and may require review on legacy IoT stacks", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	}

	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "_NULL_"):
		return TLSRiskClassification{RiskKind: "null_cipher", Severity: SeverityHigh, Reason: "NULL encryption or authentication was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "EXPORT"):
		return TLSRiskClassification{RiskKind: "export_cipher", Severity: SeverityHigh, Reason: "EXPORT-grade cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "RC4"):
		return TLSRiskClassification{RiskKind: "rc4_cipher", Severity: SeverityWarning, Reason: "RC4-based cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "3DES"):
		return TLSRiskClassification{RiskKind: "3des_cipher", Severity: SeverityWarning, Reason: "3DES-based cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "_DES_"):
		return TLSRiskClassification{RiskKind: "des_cipher", Severity: SeverityWarning, Reason: "single-DES cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "ANON"):
		return TLSRiskClassification{RiskKind: "anonymous_cipher", Severity: SeverityHigh, Reason: "anonymous key exchange cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "MD5"):
		return TLSRiskClassification{RiskKind: "md5_cipher", Severity: SeverityWarning, Reason: "MD5-based cipher suite was observed", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	case strings.Contains(upper, "_CBC_"):
		return TLSRiskClassification{RiskKind: "cbc_cipher", Severity: SeverityLow, Reason: "CBC-mode TLS cipher suite was observed and may require review on legacy IoT stacks", ObservedValue: name, SelectedOrOffered: selectedOrOffered}, true
	default:
		return TLSRiskClassification{}, false
	}
}

func ClassifyOfferedTLSCiphers(cipherSuites []uint16) []TLSRiskClassification {
	if len(cipherSuites) == 0 {
		return nil
	}
	out := make([]TLSRiskClassification, 0, len(cipherSuites))
	seen := map[uint16]struct{}{}
	for _, id := range cipherSuites {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if classification, ok := ClassifyTLSCipherSuite(id, "offered"); ok {
			out = append(out, classification)
		}
	}
	return out
}

// HasModernOfferedTLSCipher reports whether at least one AEAD suite (TLS 1.3
// suites, or GCM / ChaCha20-Poly1305 / CCM) was offered. Unknown IDs such as
// GREASE values or TLS_EMPTY_RENEGOTIATION_INFO_SCSV are not cipher suites a
// connection can use, so they do not count as modern.
func HasModernOfferedTLSCipher(cipherSuites []uint16) bool {
	for _, id := range cipherSuites {
		if id >= 0x1301 && id <= 0x1305 {
			return true
		}
		upper := strings.ToUpper(TLSCipherSuiteName(id))
		if strings.Contains(upper, "_GCM_") || strings.HasSuffix(upper, "_GCM") ||
			strings.Contains(upper, "CHACHA20") || strings.Contains(upper, "_CCM") {
			return true
		}
	}
	return false
}

func TLSCertificateAnomalySignals(ctx *Context) []string {
	if ctx == nil || ctx.TLSServerInfo == nil || ctx.TLSServerInfo.Cert == nil {
		return nil
	}

	var now time.Time
	if ctx.NowUnix > 0 {
		now = time.Unix(ctx.NowUnix, 0)
	}
	cert := ctx.TLSServerInfo.Cert
	signals := make([]string, 0, 4)
	if cert.SelfSigned {
		signals = append(signals, "self_signed_cert")
	}
	if !cert.NotAfter.IsZero() && !now.IsZero() && now.After(cert.NotAfter) {
		signals = append(signals, "expired_cert")
	}
	if !cert.NotBefore.IsZero() && !now.IsZero() && now.Before(cert.NotBefore) {
		signals = append(signals, "not_yet_valid_cert")
	}

	sni := safeTrim(ctx.TLSInfo)
	if sni != "" && !certLooksRelatedToSNI(cert, sni) {
		signals = append(signals, "cert_sni_mismatch")
	}
	return signals
}

var tlsCipherSuiteNames = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
	0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x001C: "TLS_FORTEZZA_KEA_WITH_NULL_SHA",
	0x001D: "TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
	0x001E: "TLS_KRB5_WITH_DES_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

// parseExtensions fills info from the extension block and reports whether
// the block is well formed (every extension length consistent and the block
// consumed exactly). A malformed block must not yield a partial result:
// silently dropping later extensions such as supported_versions made a
// TLS 1.3 client look like a legacy one (found by differential fuzzing
// against crypto/tls, internal/parserdiff).
func parseExtensions(exts []byte, info *TLSClientHelloInfo) bool {
	j := 0
	for j+4 <= len(exts) {
		typ := binary.BigEndian.Uint16(exts[j : j+2])
		l := int(binary.BigEndian.Uint16(exts[j+2 : j+4]))
		j += 4

		if l < 0 || j+l > len(exts) {
			return false
		}

		body := exts[j : j+l]
		j += l

		info.Extensions = append(info.Extensions, typ)

		switch typ {
		// The fields Quarant reports must be exactly well formed (RFC 8446
		// §4.2; OpenSSL and crypto/tls reject trailing or short data).
		case 0:
			name, ok := parseSNIExtension(body)
			if !ok {
				return false
			}
			info.SNI = name
		case 10:
			if len(body) < 2 {
				return false
			}
			n := int(binary.BigEndian.Uint16(body[:2]))
			if 2+n != len(body) || n%2 != 0 {
				return false
			}
			for k := 2; k+2 <= 2+n; k += 2 {
				info.SupportedGroups = append(info.SupportedGroups, binary.BigEndian.Uint16(body[k:k+2]))
			}
		case 11:
			if len(body) < 1 {
				return false
			}
			n := int(body[0])
			if 1+n != len(body) {
				return false
			}
			info.ECPointFormats = append(info.ECPointFormats, body[1:1+n]...)
		case 43:
			if len(body) < 1 {
				return false
			}
			n := int(body[0])
			if n <= 0 || 1+n != len(body) || n%2 != 0 {
				return false
			}
			for k := 1; k < 1+n; k += 2 {
				info.SupportedVersions = append(info.SupportedVersions, binary.BigEndian.Uint16(body[k:k+2]))
			}
		}
	}
	return j == len(exts)
}

func DetectTLSClientHello(data []byte) (TLSClientHelloInfo, bool) {
	var info TLSClientHelloInfo

	// A TLS client sends its ClientHello as the first bytes of the
	// connection, so only offset 0 is parsed. Scanning for a 0x16 byte
	// anywhere let non-TLS payload (or crafted data) produce a phantom
	// ClientHello with nonsense versions (found by differential fuzzing).
	for off := 0; off == 0 && off+5 <= len(data); off++ {
		if data[off] != 22 || data[off+1] != 3 {
			continue
		}
		info = TLSClientHelloInfo{}
		recVer := binary.BigEndian.Uint16(data[off+1 : off+3])
		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))

		if recLen <= 0 || off+5+recLen > len(data) {
			continue
		}

		rec := data[off+5 : off+5+recLen]
		if len(rec) < 4 {
			continue
		}

		hsType := rec[0]
		if hsType != 1 {
			continue
		}

		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		if hsLen <= 0 || 4+hsLen > len(rec) {
			continue
		}

		ch := rec[4 : 4+hsLen]
		if len(ch) < 2+32+1 {
			continue
		}

		info.RecordVersion = recVer
		info.ClientVersion = binary.BigEndian.Uint16(ch[0:2])

		i := 2 + 32
		sidLen := int(ch[i])
		i++
		if i+sidLen > len(ch) {
			continue
		}
		i += sidLen

		if i+2 > len(ch) {
			continue
		}
		csLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
		i += 2
		if csLen < 2 || i+csLen > len(ch) || csLen%2 != 0 {
			continue
		}
		for k := i; k < i+csLen; k += 2 {
			info.CipherSuites = append(info.CipherSuites, binary.BigEndian.Uint16(ch[k:k+2]))
		}
		i += csLen

		// compression_methods is mandatory (RFC 8446 §4.1.2).
		if i >= len(ch) {
			continue
		}
		cmLen := int(ch[i])
		i++
		if i+cmLen > len(ch) {
			continue
		}
		i += cmLen

		if i == len(ch) {
			return info, true
		}
		if i+2 > len(ch) {
			continue
		}
		extLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
		i += 2
		// The extension block must end exactly where the ClientHello ends.
		if extLen < 0 || i+extLen != len(ch) {
			continue
		}
		exts := ch[i : i+extLen]

		if !parseExtensions(exts, &info) {
			continue
		}
		return info, true
	}

	return info, false
}

// parseSNIExtension validates a ClientHello server_name extension body the
// way crypto/tls does: a non-empty list of (type, non-empty name) entries, at
// most one host_name, no trailing dot. ok is false for a malformed body.
func parseSNIExtension(body []byte) (string, bool) {
	if len(body) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(body[:2]))
	if listLen == 0 || 2+listLen != len(body) {
		return "", false
	}
	name := ""
	for k := 2; k < len(body); {
		if k+3 > len(body) {
			return "", false
		}
		nameType := body[k]
		nameLen := int(binary.BigEndian.Uint16(body[k+1 : k+3]))
		k += 3
		if nameLen == 0 || k+nameLen > len(body) {
			return "", false
		}
		if nameType == 0 {
			if name != "" {
				return "", false
			}
			name = string(body[k : k+nameLen])
			if strings.HasSuffix(name, ".") {
				return "", false
			}
		}
		k += nameLen
	}
	return name, true
}
