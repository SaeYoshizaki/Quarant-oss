package rules

import (
	"strings"
	"testing"
	"time"

	"quarant/analyzer/knowledge"
)

func TestI7TLSWeakVersionObservedTLS10(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		SrcIP:   "192.168.0.10",
		SrcPort: 40000,
		DstIP:   "203.0.113.10",
		DstPort: 443,
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion: 0x0301,
			SNI:           "legacy.example",
		},
	}

	match, ok := (&I7TLSWeakVersionRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected deprecated TLS version signal")
	}
	if match.Type != "I7_TLS_WEAK_VERSION_OBSERVED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	for _, want := range []string{"tls_version=TLS1.0", "sni=legacy.example", "payload_decrypted=false"} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got: %s", want, match.Evidence)
		}
	}
}

// SSL 3.0 was missed before O2: only TLS 1.0 and 1.1 counted as old.
func TestI7TLSWeakVersionObservedSSL30(t *testing.T) {
	ctx := &Context{
		TLS:           true,
		TLSInfo:       &TLSClientHelloInfo{ClientVersion: 0x0300},
		TLSServerInfo: &TLSServerInfo{ServerVersion: 0x0300},
	}
	match, ok := (&I7TLSWeakVersionRule{}).Apply(ctx)
	if !ok || !strings.Contains(match.Evidence, "tls_version=SSL3.0") {
		t.Fatalf("SSL 3.0: ok=%v %s", ok, match.Evidence)
	}
	ctx.TLSServerInfo = nil
	if _, ok := (&I7TLSWeakVersionRule{}).Apply(ctx); !ok {
		t.Fatal("SSL 3.0 as the client's highest offer")
	}
}

func TestI7TLSWeakVersionDoesNotMisclassifyWhenSupportedVersionsIncludesTLS13(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion:     0x0303,
			SupportedVersions: []uint16{0x0304, 0x0303},
			SNI:               "modern.example",
		},
	}

	if _, ok := (&I7TLSWeakVersionRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak version signal when supported_versions includes TLS 1.3")
	}
}

func TestI7TLSWeakVersionObservedTLS11FromServerHello(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{ClientVersion: 0x0303},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion: 0x0302,
		},
	}

	match, ok := (&I7TLSWeakVersionRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected TLS 1.1 signal from server metadata")
	}
	if !strings.Contains(match.Evidence, "tls_version=TLS1.1") {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7TLSWeakCipherSuiteObserved(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		SrcIP:   "192.168.0.10",
		SrcPort: 40000,
		DstIP:   "203.0.113.10",
		DstPort: 443,
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion: 0x0303,
			SNI:           "legacy.example",
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion:  0x0303,
			SelectedCipher: 0x0005,
		},
	}

	match, ok := (&I7TLSWeakCipherSuiteRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected weak cipher suite signal")
	}
	if match.Type != "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	for _, want := range []string{"cipher_suite_name=TLS_RSA_WITH_RC4_128_SHA", "cipher_suite_id=0x0005", "selected_or_offered=selected", "tls_version=TLS1.2", "sni=legacy.example"} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got: %s", want, match.Evidence)
		}
	}
}

func TestI7TLSWeakCipherSelectedObserved(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion: 0x0303,
			SNI:           "legacy.example",
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion:  0x0303,
			SelectedCipher: 0x0005,
		},
	}

	match, ok := (&I7TLSWeakCipherSelectedRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected selected weak cipher signal")
	}
	if match.Type != "I7_TLS_WEAK_CIPHER_SELECTED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	for _, want := range []string{"cipher_suite_name=TLS_RSA_WITH_RC4_128_SHA", "cipher_suite_id=0x0005", "selected_or_offered=selected", "payload_decrypted=false"} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got: %s", want, match.Evidence)
		}
	}
	if match.ObservedFact == "" || match.Inference == "" || match.Limitation == "" || match.Recommendation == "" || match.Confidence == "" {
		t.Fatalf("expected metadata fields to be populated: %+v", match)
	}
	if !containsAll(match.OWASPTags, "I7") {
		t.Fatalf("expected I7 tag, got: %v", match.OWASPTags)
	}
}

func TestI7TLSLegacyCipherOfferedObserved(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		SrcIP:   "192.168.0.10",
		SrcPort: 40000,
		DstIP:   "203.0.113.10",
		DstPort: 443,
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion:     0x0303,
			SupportedVersions: []uint16{0x0304, 0x0303},
			SNI:               "legacy.example",
			CipherSuites:      []uint16{0x0000, 0x0003, 0x0005, 0x000A, 0x1301},
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion:  0x0304,
			SelectedCipher: 0x1301,
		},
	}

	match, ok := (&I7TLSLegacyCipherOfferedRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected offered legacy cipher signal")
	}
	if match.Type != "I7_TLS_WEAK_CIPHER_OFFERED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	for _, want := range []string{"client_supported_versions=TLS1.3,TLS1.2", "cipher_suite_name=", "cipher_suite_id=0x0000,0x0003,0x0005,0x000A", "selected_or_offered=offered", "NULL", "EXPORT", "RC4", "3DES", "payload_decrypted=false"} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got: %s", want, match.Evidence)
		}
	}
	if match.ObservedFact == "" || match.Inference == "" || match.Limitation == "" || match.Recommendation == "" || match.Confidence == "" {
		t.Fatalf("expected metadata fields to be populated: %+v", match)
	}
	if !containsAll(match.OWASPTags, "I7") {
		t.Fatalf("expected I7 tag, got: %v", match.OWASPTags)
	}
}

func TestI7TLSOnlyLegacyCiphersOfferedObserved(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion:     0x0303,
			SupportedVersions: []uint16{0x0303},
			SNI:               "legacy-only.example",
			CipherSuites:      []uint16{0x0005, 0x000A},
		},
	}

	match, ok := (&I7TLSOnlyLegacyCiphersOfferedRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected only legacy ciphers offered signal")
	}
	if match.Type != "I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
}

func TestI7TLSWeakCipherNotObservedWhenOnlyOfferedCipherIsWeak(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion:     0x0303,
			SupportedVersions: []uint16{0x0304, 0x0303},
			SNI:               "mixed.example",
			CipherSuites:      []uint16{0x0005, 0x1301},
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion:  0x0304,
			SelectedCipher: 0x1301,
		},
	}

	if _, ok := (&I7TLSWeakCipherSuiteRule{}).Apply(ctx); ok {
		t.Fatal("did not expect selected weak cipher signal when selected cipher is modern")
	}
	if _, ok := (&I7TLSWeakCipherSelectedRule{}).Apply(ctx); ok {
		t.Fatal("did not expect selected weak cipher event when selected cipher is modern")
	}
	if _, ok := (&I7TLSLegacyCipherOfferedRule{}).Apply(ctx); !ok {
		t.Fatal("expected offered weak cipher signal")
	}
}

func TestI7TLSSafeVersionAndCipherDoNotFire(t *testing.T) {
	ctx := &Context{
		NowUnix: time.Now().Unix(),
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion:     0x0303,
			SupportedVersions: []uint16{0x0304, 0x0303},
			SNI:               "api.vendor.example",
			CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion:  0x0304,
			SelectedCipher: 0x1301,
		},
	}

	if _, ok := (&I7TLSWeakVersionRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak version signal for modern TLS")
	}
	if _, ok := (&I7TLSWeakCipherSuiteRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak cipher signal for modern TLS")
	}
	if _, ok := (&I7TLSLegacyCipherOfferedRule{}).Apply(ctx); ok {
		t.Fatal("did not expect offered weak cipher signal for modern TLS")
	}
	if _, ok := (&I7TLSOnlyLegacyCiphersOfferedRule{}).Apply(ctx); ok {
		t.Fatal("did not expect only-legacy cipher signal for modern TLS")
	}
}

func TestI7TLSCertificateAnomalyObserved(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	ctx := &Context{
		NowUnix: now.Unix(),
		SrcIP:   "192.168.0.10",
		SrcPort: 40000,
		DstIP:   "203.0.113.10",
		DstPort: 443,
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion: 0x0303,
			SNI:           "api.vendor.example",
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion: 0x0303,
			Cert: &TLSCertificateInfo{
				Subject:    "other.example",
				Issuer:     "other.example",
				SANs:       []string{"other.example"},
				SelfSigned: true,
				NotBefore:  now.Add(-48 * time.Hour),
				NotAfter:   now.Add(-24 * time.Hour),
			},
		},
	}

	match, ok := (&I7TLSCertificateAnomalyRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected certificate anomaly signal")
	}
	if match.Type != "I7_TLS_CERTIFICATE_ANOMALY_OBSERVED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	for _, want := range []string{"self_signed_cert", "expired_cert", "cert_sni_mismatch", "payload_decrypted=false"} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got: %s", want, match.Evidence)
		}
	}
}

func TestI7TLSCertificateAnomalySuppressedForUpdateSpecificFlow(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	ctx := &Context{
		NowUnix: now.Unix(),
		DstIP:   "203.0.113.10",
		TLS:     true,
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion: 0x0303,
			SNI:           "firmware.vendor.example",
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion: 0x0303,
			Cert: &TLSCertificateInfo{
				Subject:    "firmware.vendor.example",
				SANs:       []string{"firmware.vendor.example"},
				SelfSigned: true,
				NotBefore:  now.Add(-24 * time.Hour),
				NotAfter:   now.Add(24 * time.Hour),
			},
		},
	}

	if _, ok := (&I7TLSCertificateAnomalyRule{}).Apply(ctx); ok {
		t.Fatal("did not expect general TLS certificate anomaly on update-specific flow")
	}
}

func TestI6TLSUnexpectedSNIObserved(t *testing.T) {
	db := &knowledge.DB{
		DeviceCategories: &knowledge.DeviceCategories{Categories: []string{"Camera"}},
		BehaviorBaselines: knowledge.CategoryBehaviorBaselines{
			"Camera": {
				ExpectedProtocols:  []string{"tls"},
				PlaintextTolerance: "low",
			},
		},
		CategoryInference: &knowledge.CategoryInferenceDB{
			Categories: map[string]knowledge.CategoryInferenceEntry{
				"Camera": {
					Category:              "Camera",
					RepresentativeDomains: []string{"camera-vendor.example"},
					EcosystemDomains:      []string{"camera-vendor.example"},
					ConfidenceLevel:       "high",
				},
			},
		},
	}

	ctx := &Context{
		DstIP:                "203.0.113.10",
		DstPort:              443,
		TLS:                  true,
		DeviceCategory:       "Camera",
		LocalDeviceCategory:  "Camera",
		FlowDeviceCategory:   "Camera",
		LocalInferenceSource: "known",
		FlowInferenceSource:  "known",
		TLSInfo: &TLSClientHelloInfo{
			SNI: "unexpected.example",
		},
	}

	matches := (&I6PrivacyRule{db: db}).ApplyAll(ctx)
	found := false
	for _, match := range matches {
		if match.RuleID == "I6_TLS_UNEXPECTED_SNI_OBSERVED" {
			found = true
			if match.Severity != SeverityLow {
				t.Fatalf("expected LOW severity, got %s", match.Severity)
			}
			if !strings.Contains(match.Evidence, "sni=unexpected.example") {
				t.Fatalf("unexpected evidence: %s", match.Evidence)
			}
		}
	}
	if !found {
		t.Fatal("expected unexpected SNI observation")
	}
}
