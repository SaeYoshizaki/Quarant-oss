package device

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"quarant/analyzer/knowledge"
)

var (
	familySignatureOnce sync.Once
	familySignatures    []knowledge.DeviceFamilySignature
)

func setDeviceFamilySignaturesForTest(signatures []knowledge.DeviceFamilySignature) {
	familySignatureOnce = sync.Once{}
	familySignatures = signatures
}

func defaultDeviceFamilySignatures() []knowledge.DeviceFamilySignature {
	familySignatureOnce.Do(func() {
		db, err := knowledge.LoadDeviceFamilySignatures()
		if err == nil && db != nil {
			familySignatures = db.Families
			return
		}

		var fallback knowledge.DeviceFamilySignatures
		path := filepath.Join("..", "..", "knowledge", "device_family_signatures.json")
		if data, readErr := os.ReadFile(path); readErr == nil && json.Unmarshal(data, &fallback) == nil {
			familySignatures = fallback.Families
		}
	})
	return familySignatures
}

func recomputeDeviceIdentity(d *DeviceProfile) {
	if d == nil {
		return
	}

	typeScores, vendorScores := recomputeLegacyTypeVendorIdentity(d)
	bestType, bestTypeScore := bestScoredLabel(typeScores, d.DeviceType)
	bestVendor, bestVendorScore := bestScoredLabel(vendorScores, d.Vendor)
	knownScore := bestTypeScore + bestVendorScore

	d.TypeScores = typeScores
	d.VendorScores = vendorScores
	d.Vendor = bestVendor
	d.KnownDeviceType = bestType
	d.KnownConfidence = knownScore
	refreshClassification(d)

	category := recomputeCategoryIdentity(d)
	signatures := defaultDeviceFamilySignatures()
	family := recomputeFamilyIdentity(d, category, signatures)
	vendor := recomputeVendorIdentity(d, vendorScores, family, signatures)

	d.FamilyScores = family.FamilyScores
	d.Identity = DeviceIdentity{
		CategoryCandidate:   category.CategoryCandidate,
		VendorCandidate:     vendor.VendorCandidate,
		FamilyCandidate:     family.FamilyCandidate,
		CategoryConfidence:  category.CategoryConfidence,
		VendorConfidence:    vendor.VendorConfidence,
		FamilyConfidence:    family.FamilyConfidence,
		CategoryScore:       category.CategoryScore,
		VendorScore:         vendor.VendorScore,
		FamilyScore:         family.FamilyScore,
		CategoryReasons:     category.CategoryReasons,
		VendorReasons:       vendor.VendorReasons,
		FamilyReasons:       family.FamilyReasons,
		CategoryScores:      category.CategoryScores,
		VendorScores:        vendor.VendorScores,
		FamilyScores:        family.FamilyScores,
		FamilySignalTypes:   family.FamilySignalTypes,
		FamilyEvidenceCount: family.FamilyEvidenceCount,
	}
}

func recomputeLegacyTypeVendorIdentity(d *DeviceProfile) (map[string]float64, map[string]float64) {
	typeScores := map[string]float64{}
	vendorScores := map[string]float64{}

	for s := range d.Servers {
		server := strings.ToLower(s)

		if strings.Contains(server, "goahead") {
			addScore(typeScores, "IP Camera", 0.2)
		}
		if strings.Contains(server, "boa") {
			addScore(typeScores, "IoT Device", 0.1)
		}
	}

	for h := range d.Hosts {
		host := strings.ToLower(h)

		switch {
		case strings.Contains(host, "tplinkcloud") || strings.Contains(host, "kasa"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "Smart Home Controller", 0.5)
		case strings.Contains(host, "smartthings") || strings.Contains(host, "meethue"):
			addScore(typeScores, "Smart Home Hub", 0.5)
		case strings.Contains(host, "switch-bot") ||
			strings.Contains(host, "ewelink") ||
			strings.Contains(host, "shelly") ||
			strings.Contains(host, "tuyaus") ||
			strings.Contains(host, "meross"):
			addScore(typeScores, "Smart Home Controller", 0.4)
		case strings.Contains(host, "tapo"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(host, "hikvision"):
			addScore(vendorScores, "Hikvision", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(host, "reolink"):
			addScore(vendorScores, "Reolink", 0.3)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(host, "alexa") || strings.Contains(host, "assistant.google") || strings.Contains(host, "siri.apple"):
			addScore(typeScores, "Voice Assistant Speaker", 0.4)
		case strings.Contains(host, "aqara") || strings.Contains(host, "sensor"):
			addScore(typeScores, "Sensor", 0.3)
		}
	}

	for sni := range d.SNIValues {
		value := strings.ToLower(sni)

		switch {
		case strings.Contains(value, "tplinkcloud") || strings.Contains(value, "kasa"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "Smart Home Controller", 0.5)
		case strings.Contains(value, "smartthings") || strings.Contains(value, "meethue"):
			addScore(typeScores, "Smart Home Hub", 0.5)
		case strings.Contains(value, "alexa") || strings.Contains(value, "assistant.google") || strings.Contains(value, "siri.apple"):
			addScore(typeScores, "Voice Assistant Speaker", 0.4)
		case strings.Contains(value, "hikvision"):
			addScore(vendorScores, "Hikvision", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(value, "tapo"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(value, "reolink"):
			addScore(vendorScores, "Reolink", 0.3)
			addScore(typeScores, "IP Camera", 0.4)
		}
	}

	for ua := range d.UserAgents {
		agent := strings.ToLower(strings.TrimSpace(ua))

		switch {
		case strings.Contains(agent, "tapo-camera"),
			strings.Contains(agent, "ipcamera"),
			strings.Contains(agent, "ipcam"),
			strings.Contains(agent, "camera"):
			addScore(typeScores, "IP Camera", 0.6)
			if strings.Contains(agent, "tapo") || strings.Contains(agent, "tplink") {
				addScore(vendorScores, "TP-Link", 0.3)
			}

		case strings.Contains(agent, "kasa"),
			strings.Contains(agent, "tplink-smartplug"),
			strings.Contains(agent, "tplink controller"):
			addScore(typeScores, "Smart Home Controller", 0.6)
			addScore(vendorScores, "TP-Link", 0.3)

		case strings.Contains(agent, "smartthingshub"),
			strings.Contains(agent, "smartthings hub"),
			strings.Contains(agent, "hue-bridge"),
			strings.Contains(agent, "aqara hub"):
			addScore(typeScores, "Smart Home Hub", 0.6)

		case strings.Contains(agent, "alexa"),
			strings.Contains(agent, "echo"),
			strings.Contains(agent, "assistant"),
			strings.Contains(agent, "homepod"):
			addScore(typeScores, "Voice Assistant Speaker", 0.4)

		case strings.Contains(agent, "sensor"),
			strings.Contains(agent, "aqara"),
			strings.Contains(agent, "switchbot-meter"):
			addScore(typeScores, "Sensor", 0.3)
		}
	}

	return typeScores, vendorScores
}

func recomputeCategoryIdentity(d *DeviceProfile) DeviceIdentity {
	category := d.Classification.NormalizedCategory()
	return DeviceIdentity{
		CategoryCandidate:  category,
		CategoryConfidence: d.Classification.ConfidenceLabel,
		CategoryScore:      d.Classification.ConfidenceScore,
		CategoryReasons:    append([]string(nil), d.Classification.Reasons...),
		CategoryScores:     copyScores(d.Classification.Scores),
	}
}

func recomputeVendorIdentity(d *DeviceProfile, legacyScores map[string]float64, family DeviceIdentity, signatures []knowledge.DeviceFamilySignature) DeviceIdentity {
	vendorScores, reasonsByVendor, signalStatsByVendor := scoreVendorsFromPassiveSignals(d, legacyScores, family, signatures)
	vendor, score := bestScoredLabel(vendorScores, d.Vendor)
	stats := signalStatsByVendor[vendor]
	return DeviceIdentity{
		VendorCandidate:   vendor,
		VendorConfidence:  vendorConfidenceLabel(score, stats.distinctCount(), stats.repeatedCount(), stats.strongCount(), stats.repeatedStrongCount(), family.VendorCandidate == vendor, family.FamilyConfidence),
		VendorScore:       score,
		VendorReasons:     limitStrings(reasonsByVendor[vendor], 6),
		VendorScores:      vendorScores,
		CategoryCandidate: d.Classification.NormalizedCategory(),
	}
}

func recomputeFamilyIdentity(d *DeviceProfile, category DeviceIdentity, signatures []knowledge.DeviceFamilySignature) DeviceIdentity {
	scores := map[string]float64{}
	evaluations := make([]familyEvaluation, 0, len(signatures))

	for _, signature := range signatures {
		eval := scoreFamilySignature(d, category.CategoryCandidate, signature)
		if signature.Family != "" {
			scores[signature.Family] = eval.score
		}
		evaluations = append(evaluations, eval)
	}

	sort.SliceStable(evaluations, func(i, j int) bool {
		if evaluations[i].score == evaluations[j].score {
			return evaluations[i].family < evaluations[j].family
		}
		return evaluations[i].score > evaluations[j].score
	})

	if len(evaluations) == 0 || evaluations[0].family == "" || !evaluations[0].matched {
		return DeviceIdentity{
			FamilyConfidence: "unknown",
			FamilyReasons:    []string{"insufficient_family_evidence"},
			FamilyScores:     scores,
		}
	}

	best := evaluations[0]
	if len(evaluations) > 1 && evaluations[1].matched && best.score-evaluations[1].score < 0.8 {
		return DeviceIdentity{
			FamilyConfidence: "unknown",
			FamilyReasons: []string{
				"ambiguous_family_candidates: " + best.family + "," + evaluations[1].family,
			},
			FamilyScores: scores,
		}
	}

	return DeviceIdentity{
		FamilyCandidate:     best.family,
		VendorCandidate:     best.vendor,
		FamilyConfidence:    best.confidence,
		FamilyScore:         best.score,
		FamilyReasons:       best.reasons,
		FamilyScores:        scores,
		FamilySignalTypes:   sortedKeys(best.signalTypes),
		FamilyEvidenceCount: len(best.signalTypes),
	}
}

type familyEvaluation struct {
	family              string
	vendor              string
	score               float64
	confidence          string
	reasons             []string
	signalTypes         map[string]bool
	strongSignalTypes   map[string]bool
	repeatedSignalTypes map[string]bool
	repeatedStrongTypes map[string]bool
	matched             bool
}

func isGenericFamilyPathKeyword(keyword string) bool {
	normalized := strings.ToLower(strings.TrimSpace(keyword))
	switch normalized {
	case "/api/", "/api/config", "/admin", "/setup", "/login", "/config":
		return true
	default:
		return false
	}
}

func nonGenericPathKeywords(keywords []string) []string {
	if len(keywords) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		if isGenericFamilyPathKeyword(keyword) {
			continue
		}
		filtered = append(filtered, keyword)
	}
	return filtered
}

func isGenericWebPort(port int) bool {
	return port == 80 || port == 443
}

func scoreFamilySignature(d *DeviceProfile, category string, signature knowledge.DeviceFamilySignature) familyEvaluation {
	eval := familyEvaluation{
		family:              signature.Family,
		vendor:              signature.Vendor,
		signalTypes:         map[string]bool{},
		strongSignalTypes:   map[string]bool{},
		repeatedSignalTypes: map[string]bool{},
		repeatedStrongTypes: map[string]bool{},
	}
	if signature.Family == "" {
		return eval
	}

	addKeywordMatches := func(kind string, observed map[string]bool, keywords []string, weight float64, strength string) {
		value, keyword, ok := d.observedIndexFor(kind, observed).match(keywords)
		if !ok {
			return
		}
		eval.score += weight
		eval.signalTypes[kind] = true
		if strength == "strong" {
			eval.strongSignalTypes[kind] = true
		}
		eval.reasons = appendUnique(eval.reasons, strength+" "+kind+" keyword matched: "+keyword)
		if repeat := d.IdentitySignalRepeatCount(kind, value); repeat >= 2 {
			eval.repeatedSignalTypes[kind] = true
			if strength == "strong" {
				eval.repeatedStrongTypes[kind] = true
			}
			eval.score += repeatedObservationScore(repeat, strength)
			eval.reasons = appendUnique(eval.reasons, "consistent repeated observation count >= 2: "+kind)
		}
	}

	addKeywordMatches("host", d.Hosts, strongKeywords(signature.StrongHostKeywords, signature.HostKeywords), 1.5, "strong")
	addKeywordMatches("host", d.Hosts, signature.WeakHostKeywords, 0.55, "weak")
	addKeywordMatches("sni", d.SNIValues, strongKeywords(signature.StrongSNIKeywords, signature.SNIKeywords), 1.5, "strong")
	addKeywordMatches("sni", d.SNIValues, signature.WeakSNIKeywords, 0.55, "weak")
	addKeywordMatches("ua", d.UserAgents, strongKeywords(signature.StrongUAKeywords, signature.UAKeywords), 1.3, "strong")
	addKeywordMatches("ua", d.UserAgents, signature.WeakUAKeywords, 0.45, "weak")
	addKeywordMatches("server", d.Servers, strongKeywords(signature.StrongServerKeywords, signature.ServerKeywords), 0.9, "strong")
	addKeywordMatches("server", d.Servers, signature.WeakServerKeywords, 0.3, "weak")
	addKeywordMatches("path", d.Paths, nonGenericPathKeywords(strongKeywords(signature.StrongPathKeywords, signature.PathKeywords)), 0.9, "strong")
	addKeywordMatches("path", d.Paths, nonGenericPathKeywords(signature.WeakPathKeywords), 0.35, "weak")

	for _, port := range signature.Ports {
		if port <= 0 {
			continue
		}
		if d.Ports[uint16(port)] {
			if isGenericWebPort(port) && len(eval.signalTypes) == 0 {
				continue
			}
			portScore := 0.6
			if isGenericWebPort(port) {
				portScore = 0.15
			}
			eval.score += portScore
			eval.signalTypes["port"] = true
			eval.reasons = appendUnique(eval.reasons, "port matched: "+strconv.Itoa(port))
		}
	}

	if signature.Category != "" && strings.EqualFold(category, signature.Category) {
		eval.score += 0.7
		eval.reasons = appendUnique(eval.reasons, "category consistency: "+signature.Category)
	}

	for _, ja3 := range signature.JA3Hashes {
		if d.JA3 != "" && strings.EqualFold(d.JA3, strings.TrimSpace(ja3)) {
			eval.score += 0.4
			eval.signalTypes["ja3"] = true
			eval.reasons = appendUnique(eval.reasons, "ja3 auxiliary match")
			break
		}
	}

	minScore := signature.MinScoreForMatch
	if minScore <= 0 {
		minScore = 2.4
	}

	distinctSignals := len(eval.signalTypes)
	repeatedSignals := len(eval.repeatedSignalTypes)
	strongSignals := len(eval.strongSignalTypes)
	repeatedStrongSignals := len(eval.repeatedStrongTypes)
	eval.matched = eval.score >= minScore && distinctSignals > 0
	eval.confidence = familyConfidenceLabel(eval.score, distinctSignals, repeatedSignals, strongSignals, repeatedStrongSignals, eval.matched)
	if !eval.matched {
		eval.confidence = "unknown"
	}

	return eval
}

func familyConfidenceLabel(score float64, distinctSignals, repeatedSignals, strongSignals, repeatedStrongSignals int, matched bool) string {
	if !matched {
		return "unknown"
	}
	if score >= 5.8 && distinctSignals >= 2 && repeatedSignals >= 2 && strongSignals >= 2 && repeatedStrongSignals >= 2 {
		return "strong"
	}
	if score >= 4.6 && distinctSignals >= 2 && repeatedSignals >= 2 && strongSignals >= 1 && repeatedStrongSignals >= 1 {
		return "high"
	}
	if score >= 2.8 && distinctSignals >= 2 && strongSignals >= 1 {
		return "medium"
	}
	return "low"
}

func repeatedObservationScore(count int, strength string) float64 {
	if strength == "weak" {
		if count >= 3 {
			return 0.45
		}
		return 0.3
	}
	if count >= 3 {
		return 1.0
	}
	return 0.8
}

type vendorSignalStats struct {
	signals         map[string]bool
	repeatedSignals map[string]bool
	strongSignals   map[string]bool
	repeatedStrong  map[string]bool
}

func (s vendorSignalStats) distinctCount() int {
	return len(s.signals)
}

func (s vendorSignalStats) repeatedCount() int {
	return len(s.repeatedSignals)
}

func (s vendorSignalStats) strongCount() int {
	return len(s.strongSignals)
}

func (s vendorSignalStats) repeatedStrongCount() int {
	return len(s.repeatedStrong)
}

func scoreVendorsFromPassiveSignals(d *DeviceProfile, legacyScores map[string]float64, family DeviceIdentity, signatures []knowledge.DeviceFamilySignature) (map[string]float64, map[string][]string, map[string]vendorSignalStats) {
	scores := map[string]float64{}
	reasons := map[string][]string{}
	statsByVendor := map[string]vendorSignalStats{}

	add := func(vendor, kind, reason string, score float64, repeated bool, strong bool) {
		vendor = strings.TrimSpace(vendor)
		if vendor == "" || score <= 0 {
			return
		}
		scores[vendor] += score
		reasons[vendor] = appendUnique(reasons[vendor], reason)
		stats := statsByVendor[vendor]
		if stats.signals == nil {
			stats.signals = map[string]bool{}
			stats.repeatedSignals = map[string]bool{}
			stats.strongSignals = map[string]bool{}
			stats.repeatedStrong = map[string]bool{}
		}
		if kind != "" {
			stats.signals[kind] = true
			if strong {
				stats.strongSignals[kind] = true
			}
		}
		if repeated {
			stats.repeatedSignals[kind] = true
			if strong {
				stats.repeatedStrong[kind] = true
			}
		}
		statsByVendor[vendor] = stats
	}

	for vendor, score := range legacyScores {
		if score <= 0 {
			continue
		}
		add(vendor, "legacy", "legacy vendor keyword score", score*0.6, false, false)
	}

	for _, signature := range signatures {
		vendor := strings.TrimSpace(signature.Vendor)
		if vendor == "" {
			continue
		}
		scoreVendorKeywords(d, vendor, "host", d.Hosts, strongKeywords(signature.StrongHostKeywords, signature.HostKeywords), 1.0, "strong", add)
		scoreVendorKeywords(d, vendor, "host", d.Hosts, signature.WeakHostKeywords, 0.3, "weak", add)
		scoreVendorKeywords(d, vendor, "sni", d.SNIValues, strongKeywords(signature.StrongSNIKeywords, signature.SNIKeywords), 1.0, "strong", add)
		scoreVendorKeywords(d, vendor, "sni", d.SNIValues, signature.WeakSNIKeywords, 0.3, "weak", add)
		scoreVendorKeywords(d, vendor, "ua", d.UserAgents, strongKeywords(signature.StrongUAKeywords, signature.UAKeywords), 0.8, "strong", add)
		scoreVendorKeywords(d, vendor, "ua", d.UserAgents, signature.WeakUAKeywords, 0.25, "weak", add)
		scoreVendorKeywords(d, vendor, "server", d.Servers, strongKeywords(signature.StrongServerKeywords, signature.ServerKeywords), 0.45, "strong", add)
		scoreVendorKeywords(d, vendor, "server", d.Servers, signature.WeakServerKeywords, 0.15, "weak", add)
		scoreVendorKeywords(d, vendor, "path", d.Paths, nonGenericPathKeywords(strongKeywords(signature.StrongPathKeywords, signature.PathKeywords)), 0.35, "strong", add)
		scoreVendorKeywords(d, vendor, "path", d.Paths, nonGenericPathKeywords(signature.WeakPathKeywords), 0.15, "weak", add)
	}

	if family.VendorCandidate != "" && family.FamilyCandidate != "" {
		switch family.FamilyConfidence {
		case "strong":
			add(family.VendorCandidate, "family", "family strong supports vendor: "+family.FamilyCandidate, 1.8, false, true)
		case "high":
			add(family.VendorCandidate, "family", "family high supports vendor: "+family.FamilyCandidate, 1.4, false, true)
		case "medium":
			add(family.VendorCandidate, "family", "family medium supports vendor: "+family.FamilyCandidate, 1.0, false, true)
		}
	}

	return scores, reasons, statsByVendor
}

func scoreVendorKeywords(d *DeviceProfile, vendor, kind string, observed map[string]bool, keywords []string, weight float64, strength string, add func(string, string, string, float64, bool, bool)) {
	value, keyword, ok := d.observedIndexFor(kind, observed).match(keywords)
	if !ok {
		return
	}
	repeated := d.IdentitySignalRepeatCount(kind, value) >= 2
	score := weight
	if repeated {
		score += repeatedObservationScore(d.IdentitySignalRepeatCount(kind, value), strength) * 0.5
	}
	add(vendor, kind, strength+" "+kind+" keyword matched: "+keyword, score, repeated, strength == "strong")
}

func vendorConfidenceLabel(score float64, distinctSignals, repeatedSignals, strongSignals, repeatedStrongSignals int, familyMatches bool, familyConfidence string) string {
	if familyMatches && familyConfidence == "strong" && score >= 3.2 {
		return "high"
	}
	if familyMatches && familyConfidence == "high" && score >= 2.8 {
		return "high"
	}
	if score >= 5.0 && distinctSignals >= 2 && repeatedSignals >= 2 && strongSignals >= 1 && repeatedStrongSignals >= 1 {
		return "strong"
	}
	if score >= 3.8 && distinctSignals >= 2 && strongSignals >= 1 && (repeatedStrongSignals >= 1 || confidenceRank(familyConfidence) >= confidenceRank("high")) {
		return "high"
	}
	if score >= 1.8 && (distinctSignals >= 2 || confidenceRank(familyConfidence) >= confidenceRank("medium")) {
		return "medium"
	}
	if score >= 0.4 {
		return "low"
	}
	return "unknown"
}

func confidenceRank(label string) int {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "strong":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func confidenceLabel(score, low, medium, high, strong float64) string {
	switch {
	case score >= strong:
		return "strong"
	case score >= high:
		return "high"
	case score >= medium:
		return "medium"
	case score >= low:
		return "low"
	default:
		return "unknown"
	}
}

func strongKeywords(primary, legacy []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return legacy
}

func limitStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) <= limit {
		out := make([]string, len(values))
		copy(out, values)
		return out
	}
	out := make([]string, limit)
	copy(out, values[:limit])
	return out
}

func vendorReasons(d *DeviceProfile, vendor string, limit int) []string {
	if d == nil || vendor == "" || limit <= 0 {
		return nil
	}
	vendorLower := strings.ToLower(vendor)
	aliases := []string{vendorLower}
	switch vendorLower {
	case "tp-link":
		aliases = append(aliases, "tplink", "tplinkcloud", "kasa", "tapo")
	case "hikvision":
		aliases = append(aliases, "hik-connect")
	case "philips":
		aliases = append(aliases, "meethue", "hue")
	}

	reasons := []string{}
	add := func(reason string) {
		if len(reasons) < limit {
			reasons = appendUnique(reasons, reason)
		}
	}
	match := func(kind, value string) {
		valueLower := strings.ToLower(value)
		for _, alias := range aliases {
			if alias != "" && strings.Contains(valueLower, alias) {
				add(kind + " keyword matched: " + alias)
				return
			}
		}
	}
	for value := range d.Hosts {
		match("host", value)
	}
	for value := range d.SNIValues {
		match("sni", value)
	}
	for value := range d.UserAgents {
		match("ua", value)
	}
	return reasons
}

func copyScores(in map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
