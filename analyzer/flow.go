package analyzer

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"quarant/analyzer/behavior"
	"quarant/analyzer/device"
	"quarant/analyzer/knowledge"
	"quarant/analyzer/rules"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FlowHandler struct {
	eventSink       *JSONLSink
	flowSink        *JSONLSink
	observationSink *JSONLSink
	cache           *FlowCache
	debug           bool
	devices         *device.Store
	knowledge       *knowledge.DB
	lastCleanup     time.Time
	localNets       LocalNetworks

	// mu serializes packet handling with snapshot readers (the periodic
	// inventory writer runs in another goroutine).
	mu      sync.Mutex
	macToIP map[string]string
	// macChangeReported rate-limits binding-change events per IP/MAC pair.
	macChangeReported map[string]time.Time
	// guesses counts failed credential attempts per (device, client).
	guesses map[string]*guessState
	// streamReported rate-limits unauthenticated stream findings.
	streamReported map[string]time.Time
	pendingDHCP    map[string]pendingDHCP

	deviceReported map[string]bool
	// payloadReported de-duplicates the protocol-independent payload checks.
	payloadReported  map[string]bool
	i5Cache          map[string]i5CacheEntry
	behavior         *behavior.Analyzer
	dnsNames         map[string]string
	lastBehaviorEval time.Time
}

// SetLocalNetworks restricts device tracking to the given ranges. Hosts
// outside them are treated as remote peers, never as devices.
func (h *FlowHandler) SetLocalNetworks(ln LocalNetworks) {
	if h != nil {
		h.localNets = ln
	}
}

func (h *FlowHandler) isLocal(ip string) bool {
	return h.localNets.Contains(ip)
}

// localDevice returns the profile for ip when it is inside the monitored
// network, or nil for remote hosts.
func (h *FlowHandler) localDevice(ip string) *device.DeviceProfile {
	if h == nil || h.devices == nil || !h.isLocal(ip) {
		return nil
	}
	return h.devices.GetOrCreate(ip)
}

// flowDeviceIP picks the monitored device a flow belongs to: the client
// (initiator) when it is local, otherwise the server when it is local.
// Flows between two remote hosts have no device.
func (h *FlowHandler) flowDeviceIP(st *FlowState) string {
	switch {
	case st == nil:
		return ""
	case h.isLocal(st.SrcIP):
		return st.SrcIP
	case h.isLocal(st.DstIP):
		return st.DstIP
	default:
		return ""
	}
}

// serverSideFindings are rules that describe the service a server exposes
// (listening Telnet, an HTTP admin page) rather than what a client sent.
// When the server is a local device it is the one at risk, not the client
// that happened to connect to it.
func isServerSideFinding(eventType string) bool {
	switch {
	case strings.HasPrefix(eventType, "I2_") && (strings.HasSuffix(eventType, "_SERVICE_OBSERVED") || strings.HasSuffix(eventType, "_PROTOCOL_EVIDENCE")):
		return true
	case strings.HasPrefix(eventType, "I2_HTTP_ADMIN_"),
		// Plaintext request findings toward a local server describe the
		// server's interface (e.g. a camera web UI accepting Basic auth).
		strings.HasPrefix(eventType, "INSECURE_HTTP"),
		strings.HasPrefix(eventType, "INSECURE_MQTT"),
		strings.HasPrefix(eventType, "INSECURE_TELNET"),
		strings.HasPrefix(eventType, "I3_"),
		eventType == "I3_MANAGEMENT_API_EXPOSED",
		eventType == "I9_SETUP_ENDPOINT_STILL_ACTIVE":
		return true
	default:
		return false
	}
}

// affectedDeviceIP decides which local device a finding is attributed to.
func (h *FlowHandler) affectedDeviceIP(eventType string, st *FlowState) string {
	if st == nil {
		return ""
	}
	if isServerSideFinding(eventType) && h.isLocal(st.DstIP) {
		return st.DstIP
	}
	// A local TLS server that picked a deprecated version although the client
	// offered a newer one is the device whose cryptography is weak (E11: a
	// camera chose TLS 1.0 for a phone offering TLS 1.2).
	if eventType == "I7_TLS_WEAK_VERSION_OBSERVED" && h.isLocal(st.DstIP) &&
		rules.ServerChoseWeakerTLS(st.TLSClientInfo, st.TLSServerInfo) {
		return st.DstIP
	}
	return h.flowDeviceIP(st)
}

// flowCleanupInterval bounds how often idle flows are swept. It is measured in
// capture time so that offline analysis is deterministic.
const flowCleanupInterval = 10 * time.Second

// FlowIdleTimeout is how long a flow key stays one flow without packets.
// Each rule reports once per flow, so a connection that reuses
// the key within this time is not reported again.
const FlowIdleTimeout = time.Hour

// finishFlow writes the final record of a flow leaving the cache and hands it
// to the behaviour analyzer.
func (h *FlowHandler) finishFlow(now time.Time, key string, st *FlowState) {
	h.writeFlowRecordSnapshot(now, key, st, true)
	h.recordConnection(st)
}

// packetTime returns the capture timestamp of the packet. Offline analysis must
// use the time the packet was recorded, not the time it was analyzed, so that
// events, flows and device histories line up with the traffic itself. Packets
// without capture metadata (e.g. built in tests) fall back to the wall clock.
func packetTime(packet gopacket.Packet) time.Time {
	if md := packet.Metadata(); md != nil && !md.Timestamp.IsZero() {
		return md.Timestamp
	}
	return time.Now()
}

// Flush writes a final record for every flow still held in the cache. It is
// called by the Engine when the input ends so that the last byte and packet
// counters of each flow are not lost.
func (h *FlowHandler) Flush(at time.Time) {
	if h == nil || h.cache == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache.Drain(func(key string, st *FlowState) {
		now := at
		if now.IsZero() || now.Before(st.LastSeen) {
			now = st.LastSeen
		}
		h.finishFlow(now, key, st)
	})
	h.evaluateBehavior(at)
}

func NewFlowHandler(eventSink, flowSink *JSONLSink, debug bool, db *knowledge.DB) *FlowHandler {
	return NewFlowHandlerWithObservations(eventSink, flowSink, nil, debug, db)
}

func NewFlowHandlerWithObservations(eventSink, flowSink, observationSink *JSONLSink, debug bool, db *knowledge.DB) *FlowHandler {
	return &FlowHandler{
		eventSink:       eventSink,
		flowSink:        flowSink,
		observationSink: observationSink,
		cache:           NewFlowCache(16*1024, FlowIdleTimeout),
		debug:           debug,
		devices:         device.NewStore(),
		knowledge:       db,
	}
}

func (h *FlowHandler) DeviceInventory() []device.InventorySnapshot {
	if h == nil || h.devices == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.devices.Snapshots()
}

// TCPFlowKey is the flow key Quarant uses for a TCP connection, so that
// events from other analysers (Zeek) can be matched to the same flow.
func TCPFlowKey(ipSrc string, srcPort uint16, ipDst string, dstPort uint16) string {
	return flowKeyTCP(ipSrc, srcPort, ipDst, dstPort)
}

func flowKeyTCP(ipSrc string, srcPort uint16, ipDst string, dstPort uint16) string {
	a := flowEndpoint(ipSrc, srcPort)
	b := flowEndpoint(ipDst, dstPort)
	if a < b {
		return "tcp|" + a + "<->" + b
	}
	return "tcp|" + b + "<->" + a
}

func flowEndpoint(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func packetIPStrings(packet gopacket.Packet) (string, string, bool) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String(), true
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String(), true
	}
	return "", "", false
}

func isI2RiskEvent(eventType string) bool {
	switch eventType {
	case "I2_TELNET_SERVICE_OBSERVED",
		"I2_FTP_SERVICE_OBSERVED",
		"I2_RTSP_SERVICE_OBSERVED",
		"I2_MQTT_SERVICE_OBSERVED",
		"I2_COAP_SERVICE_OBSERVED",
		"I2_TELNET_PROTOCOL_EVIDENCE",
		"I2_FTP_PROTOCOL_EVIDENCE",
		"I2_RTSP_PROTOCOL_EVIDENCE",
		"I2_MQTT_PROTOCOL_EVIDENCE",
		"I2_HTTP_ADMIN_INTERFACE_SUSPECTED",
		"I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK",
		"I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED":
		return true
	default:
		return false
	}
}

func observedProtocolsForFlow(dstPort uint16, httpInfo *rules.HTTPInfo, mqttInfo *rules.MQTTInfo, telnetInfo *rules.TelnetInfo, tlsSeen bool) []string {
	protocols := map[string]bool{}

	if httpInfo != nil {
		if tlsSeen {
			protocols["https"] = true
			protocols["tls"] = true
		} else {
			protocols["http"] = true
		}
	}
	if mqttInfo != nil {
		protocols["mqtt"] = true
		if tlsSeen || dstPort == 8883 {
			protocols["tls"] = true
		}
	}
	if telnetInfo != nil {
		protocols["telnet"] = true
	}

	if service, ok := rules.InsecureServiceNameByPort(dstPort); ok {
		protocols[service] = true
	}
	if tlsSeen || rules.IsTLSPort(dstPort) {
		protocols["tls"] = true
		if httpInfo != nil || dstPort == 443 || dstPort == 8443 || dstPort == 9443 || dstPort == 10443 {
			protocols["https"] = true
		}
	}

	out := make([]string, 0, len(protocols))
	for protocol := range protocols {
		out = append(out, protocol)
	}
	sort.Strings(out)
	return out
}

func observeDeviceFlow(d *device.DeviceProfile, now time.Time, dstPort uint16, protocols []string) {
	if d == nil {
		return
	}
	d.ObserveActivity(now)
	if d.Ports == nil {
		d.Ports = map[uint16]bool{}
	}
	d.Ports[dstPort] = true
	if d.Protocols == nil {
		d.Protocols = map[string]bool{}
	}
	for _, protocol := range protocols {
		if strings.TrimSpace(protocol) == "" {
			continue
		}
		d.Protocols[protocol] = true
	}
}

func (h *FlowHandler) updateDeviceRiskFromMatch(srcIP string, m rules.Match) {
	d := h.devices.GetOrCreate(srcIP)

	switch m.Type {
	case "I2_TELNET_SERVICE_OBSERVED", "I2_TELNET_PROTOCOL_EVIDENCE":
		d.AddObservedService("telnet")
		d.AddInsecureService("telnet")
		d.AddRiskReason("telnet observed")

	case "I2_FTP_SERVICE_OBSERVED", "I2_FTP_PROTOCOL_EVIDENCE":
		d.AddObservedService("ftp")
		d.AddInsecureService("ftp")
		d.AddRiskReason("ftp observed")

	case "I2_RTSP_SERVICE_OBSERVED", "I2_RTSP_PROTOCOL_EVIDENCE":
		d.AddObservedService("rtsp")
		d.AddInsecureService("rtsp")
		d.AddRiskReason("rtsp observed")

	case "I2_MQTT_SERVICE_OBSERVED", "I2_MQTT_PROTOCOL_EVIDENCE":
		d.AddObservedService("mqtt")
		d.AddInsecureService("mqtt")
		d.AddRiskReason("mqtt observed")

	case "I2_COAP_SERVICE_OBSERVED":
		d.AddObservedService("coap")
		d.AddInsecureService("coap")
		d.AddRiskReason("coap observed")

	case "I2_HTTP_ADMIN_INTERFACE_SUSPECTED":
		d.AddObservedService("http")
		d.MarkAdminSuspected()
		d.AddRiskReason("http admin interface suspected")

	case "I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK":
		d.MarkExternalExposure()
		d.AddRiskReason("insecure service toward public network")

	case "I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED":
		d.AddObservedService("http")
		d.MarkAdminSuspected()
		d.MarkExternalExposure()
		d.AddRiskReason("http admin interface over public network")
	}

	d.RecalculateRiskScore()
}

func (h *FlowHandler) writeDeviceDebug(now time.Time, srcIP string, d *device.DeviceProfile) {
	if !h.debug {
		return
	}

	reasons := d.Classification.Reasons
	inferenceSource := string(d.Classification.InferenceSource)
	if inferenceSource == "" {
		inferenceSource = string(device.InferenceSourceUnknown)
	}
	inferredScores := d.Classification.Scores
	summary := deviceDebugSummary(d.Classification, d.DeviceType)
	detailReasons := humanizeReasons(reasons)
	identity := d.Identity

	_ = h.eventSink.Write(Event{
		Timestamp: now,
		Type:      "DEVICE_DEBUG",
		Severity:  SeverityInfo,
		Debug:     true,
		SrcIP:     srcIP,
		Message: fmt.Sprintf(
			"summary=%q detail=%q identity_state=%s identity_category=%s identity_category_confidence=%s identity_vendor=%s identity_vendor_confidence=%s identity_family=%s identity_family_confidence=%s identity_reasons=%v identity_top_category_scores=%v identity_top_vendor_scores=%v identity_top_family_scores=%v device_type=%s vendor=%s model=%s category=%s inference_source=%s confidence=%s inference_reasons=%v inferred_scores=%v ja3=%s evidence=%v risk_score=%d observed=%v insecure=%v admin=%t external=%t reasons=%v",
			summary,
			fmt.Sprintf("category=%s source=%s confidence=%s reasons=%v", d.Classification.NormalizedCategory(), inferenceSource, d.Classification.ConfidenceSummary(), detailReasons),
			identityDebugState(identity),
			identity.CategoryCandidate,
			identity.CategoryConfidence,
			identity.VendorCandidate,
			identity.VendorConfidence,
			identity.FamilyCandidate,
			identity.FamilyConfidence,
			identityDebugReasons(identity),
			topScores(identity.CategoryScores, 3),
			topScores(identity.VendorScores, 3),
			topScores(identity.FamilyScores, 3),
			d.DeviceType,
			d.Vendor,
			d.Model,
			d.Classification.NormalizedCategory(),
			inferenceSource,
			d.Classification.ConfidenceSummary(),
			detailReasons,
			inferredScores,
			d.JA3,
			d.Evidence,
			d.RiskScore,
			d.ObservedServices,
			d.InsecureServices,
			d.AdminSuspected,
			d.ExternalExposureSuspected,
			d.RiskReasons,
		),
	})
}

func identityDebugState(identity device.DeviceIdentity) string {
	familyRank := debugConfidenceRank(identity.FamilyConfidence)
	vendorRank := debugConfidenceRank(identity.VendorConfidence)
	hasFamily := strings.TrimSpace(identity.FamilyCandidate) != ""
	hasVendor := strings.TrimSpace(identity.VendorCandidate) != ""
	switch {
	case hasFamily && familyRank >= debugConfidenceRank("medium"):
		return "concrete_family"
	case hasVendor && vendorRank >= debugConfidenceRank("medium"):
		return "vendor_without_concrete_family"
	case hasFamily:
		return "family_uncertain"
	default:
		return "identity_weak"
	}
}

func identityDebugReasons(identity device.DeviceIdentity) []string {
	reasons := []string{}
	reasons = append(reasons, limitPrefixedReasons("category", identity.CategoryReasons, 2)...)
	reasons = append(reasons, limitPrefixedReasons("vendor", identity.VendorReasons, 2)...)
	reasons = append(reasons, limitPrefixedReasons("family", identity.FamilyReasons, 3)...)
	return reasons
}

func limitPrefixedReasons(prefix string, reasons []string, limit int) []string {
	out := []string{}
	for _, reason := range reasons {
		if strings.TrimSpace(reason) == "" {
			continue
		}
		out = append(out, prefix+":"+reason)
		if len(out) >= limit {
			return out
		}
	}
	return out
}

func inferenceView(category, deviceType, source, confidence string, reasons []string) rules.InferenceView {
	return rules.InferenceView{
		Category:   category,
		DeviceType: deviceType,
		Source:     source,
		Confidence: confidence,
		Reasons:    reasons,
	}
}

func humanizeReasons(reasons []string) []string {
	if len(reasons) == 0 {
		return reasons
	}

	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		trimmed := strings.TrimSpace(reason)
		if trimmed == "" {
			continue
		}
		switch trimmed {
		case "insufficient_evidence":
			out = append(out, "no strong known match and inferred score below threshold")
		default:
			out = append(out, trimmed)
		}
	}
	return out
}

func compactClassification(category, source, confidence string) string {
	return fmt.Sprintf("%s(%s,%s)", category, source, confidence)
}

func topScores(scores map[string]float64, limit int) []string {
	if len(scores) == 0 || limit <= 0 {
		return nil
	}
	type scoreEntry struct {
		label string
		score float64
	}
	entries := make([]scoreEntry, 0, len(scores))
	for label, score := range scores {
		if score <= 0 {
			continue
		}
		entries = append(entries, scoreEntry{label: label, score: score})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].score == entries[j].score {
			return entries[i].label < entries[j].label
		}
		return entries[i].score > entries[j].score
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, fmt.Sprintf("%s=%.2f", entry.label, entry.score))
	}
	return out
}

func debugConfidenceRank(label string) int {
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

func classificationSourcePhrase(source string) string {
	switch source {
	case string(device.InferenceSourceKnown):
		return "known"
	case string(device.InferenceSourceInferred):
		return "inferred"
	default:
		return "unknown"
	}
}

func deviceDebugSummary(classification device.Classification, deviceType string) string {
	category := classification.NormalizedCategory()
	source := string(classification.InferenceSource)
	if source == "" {
		source = string(device.InferenceSourceUnknown)
	}

	switch source {
	case string(device.InferenceSourceKnown):
		if deviceType != "" {
			return fmt.Sprintf("known %s device classified as %s", deviceType, category)
		}
		return fmt.Sprintf("known device classified as %s", category)
	case string(device.InferenceSourceInferred):
		return fmt.Sprintf("inferred %s device from communication hints", category)
	default:
		return "unknown device with insufficient evidence"
	}
}

func i6DebugSummary(localCategory, flowCategory, ctxCategory, localSource, flowSource, ctxSource string) string {
	if localSource == string(device.InferenceSourceUnknown) &&
		flowSource == string(device.InferenceSourceUnknown) &&
		ctxSource == string(device.InferenceSourceUnknown) &&
		localCategory == "GenericIoT" &&
		flowCategory == "GenericIoT" &&
		ctxCategory == "GenericIoT" {
		return "unknown device with insufficient evidence"
	}

	if localCategory == flowCategory && flowCategory == ctxCategory {
		return fmt.Sprintf(
			"%s %s device, flow also classified as %s",
			classificationSourcePhrase(localSource),
			localCategory,
			flowCategory,
		)
	}

	return fmt.Sprintf(
		"%s %s device, flow classified as %s, ctx=%s",
		classificationSourcePhrase(localSource),
		localCategory,
		flowCategory,
		ctxCategory,
	)
}

func i6DebugDetail(localCategory, flowCategory, ctxCategory, localSource, flowSource, ctxSource, localConfidence, flowConfidence, ctxConfidence string, localReasons, flowReasons, ctxReasons []string) string {
	return fmt.Sprintf(
		"local=%s flow=%s ctx=%s local_reasons=%v flow_reasons=%v ctx_reasons=%v",
		compactClassification(localCategory, localSource, localConfidence),
		compactClassification(flowCategory, flowSource, flowConfidence),
		compactClassification(ctxCategory, ctxSource, ctxConfidence),
		humanizeReasons(localReasons),
		humanizeReasons(flowReasons),
		humanizeReasons(ctxReasons),
	)
}

func mapKeys(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	return keys
}

func i4UpdateVisibility(d *device.DeviceProfile) string {
	if d == nil {
		return "unknown"
	}

	observedMetadata := false
	for host := range d.Hosts {
		observedMetadata = true
		if rules.I4LooksLikeObservedUpdateCommunication("", host, "") {
			return "seen"
		}
	}
	for path := range d.Paths {
		observedMetadata = true
		if rules.I4LooksLikeObservedUpdateCommunication(path, "", "") {
			return "seen"
		}
	}
	for sni := range d.SNIValues {
		observedMetadata = true
		if rules.I4LooksLikeObservedUpdateCommunication("", "", sni) {
			return "seen"
		}
	}

	if !observedMetadata {
		return "unknown"
	}
	return "not_seen"
}

func i4LegacySignals(d *device.DeviceProfile) []string {
	if d == nil {
		return nil
	}

	signals := make([]string, 0, 5)
	if d.InsecureServices["telnet"] {
		signals = append(signals, "telnet_observed")
	}
	if d.InsecureServices["ftp"] {
		signals = append(signals, "ftp_observed")
	}
	if d.AdminSuspected {
		signals = append(signals, "admin_interface")
	}
	if d.ExternalExposureSuspected {
		signals = append(signals, "external_exposure")
	}
	if d.Protocols["http"] && !d.Protocols["https"] && !d.Protocols["tls"] {
		signals = append(signals, "http_only_management")
	}

	return signals
}

func (h *FlowHandler) updateFlowState(st *FlowState, srcIP, dstIP string, srcPort, dstPort uint16, payloadLen int, serverSignal bool) {
	if st == nil {
		return
	}
	if st.SrcIP == "" {
		st.SrcIP = srcIP
		st.SrcPort = srcPort
		st.DstIP = dstIP
		st.DstPort = dstPort
	}
	st.PacketCount++

	if srcIP == st.SrcIP && srcPort == st.SrcPort && dstIP == st.DstIP && dstPort == st.DstPort {
		st.ClientBytes += int64(payloadLen)
		return
	}
	if srcIP == st.DstIP && srcPort == st.DstPort && dstIP == st.SrcIP && dstPort == st.SrcPort {
		st.ServerBytes += int64(payloadLen)
		if serverSignal {
			st.ServerResponded = true
		}
		return
	}
	st.ClientBytes += int64(payloadLen)
}

func (h *FlowHandler) updateFlowMetadata(st *FlowState, httpInfo *rules.HTTPInfo, mqttInfo *rules.MQTTInfo, telnetInfo *rules.TelnetInfo) {
	if st == nil {
		return
	}
	if httpInfo != nil {
		st.HTTPSeen = true
		if host := strings.TrimSpace(httpInfo.Headers["host"]); host != "" {
			st.HTTPHost = host
		}
		if method := strings.TrimSpace(httpInfo.Method); method != "" {
			st.HTTPMethod = method
		}
		if path := strings.TrimSpace(httpInfo.Path); path != "" {
			st.HTTPPath = path
		}
	}
	if mqttInfo != nil {
		st.MQTTSeen = true
	}
	if telnetInfo != nil {
		st.TelnetSeen = true
	}
}

func (h *FlowHandler) writeFlowRecordSnapshot(now time.Time, key string, st *FlowState, final bool) {
	if h == nil || h.flowSink == nil || st == nil {
		return
	}
	record := h.buildFlowRecord(now, key, st)
	metaFingerprint := strings.Join([]string{
		record.Protocol,
		record.AppProtocol,
		record.Host,
		record.SNI,
		record.HTTPMethod,
		record.HTTPPath,
		record.Direction,
		record.DeviceCategory,
		record.ObservedDestination,
	}, "|")
	if !final &&
		st.PacketCount > 1 &&
		st.PacketCount%10 != 0 &&
		now.Sub(st.LastFlowLogAt) < 2*time.Second &&
		metaFingerprint == st.LastFlowMetaFingerprint {
		return
	}
	_ = h.flowSink.WriteFlow(record)
	h.writeFlowObservations(record)
	st.LastFlowLogAt = now
	st.LastFlowMetaFingerprint = metaFingerprint
}

func (h *FlowHandler) buildFlowRecord(now time.Time, key string, st *FlowState) FlowRecord {
	sni := ""
	if st.TLSClientInfo != nil {
		sni = strings.TrimSpace(st.TLSClientInfo.SNI)
	}
	host := strings.TrimSpace(st.HTTPHost)
	protocol, appProtocol := classifyFlowProtocol(st)
	deviceCategory := ""
	if d := h.localDevice(h.flowDeviceIP(st)); d != nil {
		deviceCategory = normalizeDeviceCategory(d)
	}
	return FlowRecord{
		Timestamp:           now,
		FlowKey:             key,
		SrcIP:               st.SrcIP,
		SrcPort:             st.SrcPort,
		DstIP:               st.DstIP,
		DstPort:             st.DstPort,
		Protocol:            protocol,
		AppProtocol:         appProtocol,
		Host:                host,
		SNI:                 sni,
		DNSName:             h.dnsNames[st.DstIP],
		HTTPMethod:          strings.TrimSpace(st.HTTPMethod),
		HTTPPath:            strings.TrimSpace(st.HTTPPath),
		BytesOut:            st.ClientBytes,
		BytesIn:             st.ServerBytes,
		PacketCount:         st.PacketCount,
		Direction:           flowDirection(st.DstIP),
		DeviceLabel:         "",
		DeviceCategory:      deviceCategory,
		ObservedDestination: observedDestination(sni, host, firstNonEmptyString(h.dnsNames[st.DstIP], st.DstIP)),
		CaptureGaps:         st.ClientAsm.Gaps + st.ServerAsm.Gaps,
		CaptureGapBytes:     st.ClientAsm.GapBytes + st.ServerAsm.GapBytes,
		RetransmittedBytes:  st.ClientAsm.RetransmittedBytes + st.ServerAsm.RetransmittedBytes,
	}
}

func classifyFlowProtocol(st *FlowState) (string, string) {
	if st == nil {
		return "tcp", ""
	}
	if st.TLSClientSeen || st.TLSServerSeen {
		switch {
		case st.HTTPSeen:
			return "tls", "https"
		case st.MQTTSeen:
			return "tls", "mqtts"
		case st.DstPort == 443 || st.DstPort == 8443 || st.DstPort == 9443 || st.DstPort == 10443:
			return "tls", "https"
		default:
			return "tls", ""
		}
	}
	switch {
	case st.HTTPSeen:
		return "http", "http"
	case st.MQTTSeen:
		return "mqtt", "mqtt"
	case st.TelnetSeen:
		return "telnet", "telnet"
	default:
		return "tcp", ""
	}
}

func (h *FlowHandler) HandlePacket(packet gopacket.Packet) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := packetTime(packet)
	srcIP, dstIP, ok := packetIPStrings(packet)
	h.observeLinkLayer(packet, now, srcIP)
	if !ok {
		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		var dns *layers.DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns = dnsLayer.(*layers.DNS)
		} else if udp.SrcPort == 5353 || udp.DstPort == 5353 {
			// gopacket only auto-decodes DNS on port 53; mDNS uses the same
			// wire format on 5353.
			dns = decodeDNS(udp.Payload)
		}
		h.observeDiscovery(packet, now, srcIP, udp, dns)
		h.observeDNSAnswers(dstIP, dns)
		h.observeUDPActivity(now, srcIP, dstIP, uint16(udp.SrcPort), uint16(udp.DstPort), dns)
		h.writeUDPPacketObservations(now, srcIP, dstIP, uint16(udp.SrcPort), uint16(udp.DstPort), len(udp.Payload), dns)
		if dns == nil {
			h.scanUDPCredentials(now, srcIP, dstIP, uint16(udp.SrcPort), uint16(udp.DstPort), udp.Payload)
		}
		return
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	key := flowKeyTCP(srcIP, srcPort, dstIP, dstPort)
	st := h.cache.GetOrCreate(key, now)
	respondedBefore := st.ServerResponded
	bufferedBefore := len(st.ClientData) + len(st.ServerData)
	h.updateFlowState(st, srcIP, dstIP, srcPort, dstPort, len(tcp.Payload), (tcp.SYN && tcp.ACK) || len(tcp.Payload) > 0)

	// TLS is recognised by content as well as by port: on real traffic
	// 1.8-3.7% of ClientHellos used ports outside rules.IsTLSPort (IMAPS
	// 993, push services on 5228, TLS on 80, ...) and were never parsed
	// (measured with quarant parser-diff).
	fromClient := srcIP == st.SrcIP && srcPort == st.SrcPort
	// The start of the stream is found by sequence number, so a reordered
	// capture whose first data segment is not the first one still
	// recognises TLS when the real first segment arrives.
	if fromClient && len(tcp.Payload) > 0 {
		st.ClientAsm.markStart(tcp.Seq)
	}
	if fromClient && len(tcp.Payload) > 0 && !st.TLSByContent &&
		st.ClientAsm.isStreamStart(tcp.Seq, st.ClientBytes == int64(len(tcp.Payload))) && looksLikeTLSRecord(tcp.Payload) {
		st.TLSByContent = true
	}
	// STARTTLS: TLS that begins after a plaintext preamble (E12: XMPP on
	// 5222 selecting 3DES). Only after the client asked for the upgrade, so
	// a 0x16 byte inside other payload is not taken for a handshake.
	if fromClient && len(tcp.Payload) > 0 && !st.TLSByContent {
		if st.StartTLSRequested && looksLikeTLSRecord(tcp.Payload) {
			st.TLSByContent, st.StartTLS = true, true
			st.ClientData, st.ServerData = nil, nil
			st.ClientAsm.restart()
			st.ServerAsm.restart()
		} else if len(tcp.Payload) <= 512 && isStartTLSRequest(tcp.Payload) {
			st.StartTLSRequested = true
		}
	}
	if fromClient && len(tcp.Payload) > 0 && st.ClientBytes == int64(len(tcp.Payload)) && !rules.IsHTTPPort(dstPort) &&
		rules.LooksLikeHTTPRequest(tcp.Payload) {
		st.HTTPContent = true
		st.HTTPByContent = h.isLocal(dstIP)
	}
	if len(tcp.Payload) > 0 {
		h.scanTCPMedia(now, st, srcIP, dstIP, srcPort, dstPort, tcp.Payload)
	}
	httpFlow := rules.IsHTTPPort(st.DstPort) || st.HTTPByContent
	h.observeRTSP(now, st, fromClient, tcp.Payload)
	tlsClient := st.TLSByContent && fromClient
	tlsServer := st.TLSByContent && !fromClient

	captureClient := rules.NeedsPayloadCapture(dstPort) || tlsClient || (st.HTTPContent && fromClient)
	captureServer := rules.NeedsPayloadCapture(srcPort) || tlsServer || (st.HTTPByContent && !fromClient)
	capturePayload := captureClient || captureServer
	// HTTP recognised by content (st.HTTPByContent) is only used for the
	// request/response pair below: running every HTTP rule on UPnP traffic
	// turned protocol-mandated description fetches (GET /setup.xml) into
	// ~59k setup-endpoint and ~110k plaintext-HTTP findings on UNSW 2018.
	isHTTPClientToServer := rules.IsHTTPPort(dstPort)
	isTelnetClientToServer := rules.IsTelnetPort(dstPort)
	isMQTTClientToServer := rules.IsMQTTPort(dstPort)
	isTLSClientToServer := rules.IsTLSPort(dstPort) || tlsClient
	isTLSServerToClient := rules.IsTLSPort(srcPort) || tlsServer

	// Each direction goes through its own sequence-order assembler. A
	// packet travelling to the watched port is client data, as before:
	// the flow's first packet can be the server's SYN/ACK when the capture
	// starts mid-handshake, so the flow's initiator is not always the
	// client. Only when both ports are watched does the sender decide,
	// which keeps one direction's bytes out of the other's buffer.
	toServer := captureClient && (fromClient || !captureServer)
	toClient := captureServer && !toServer
	// Initial sequence numbers are recorded from the flags (SYN: client,
	// SYN/ACK: server) whatever is captured yet: TLS and HTTP found by
	// content are only known after the handshake, and without the ISN a
	// reordered first segment looked like a retransmission and was dropped.
	if tcp.SYN && !tcp.ACK {
		st.ClientAsm.syn(tcp.Seq)
	} else if tcp.SYN {
		st.ServerAsm.syn(tcp.Seq)
	}
	if len(tcp.Payload) > 0 {
		if toServer {
			h.cache.AppendClientSegment(st, tcp.Seq, tcp.Payload)
		} else if toClient {
			h.cache.AppendServerSegment(st, tcp.Seq, tcp.Payload)
		} else if fromClient {
			st.ClientAsm.hold(tcp.Seq, tcp.Payload)
		}
	}
	if tcp.ACK {
		// An acknowledgement for bytes the capture never saw proves a
		// capture gap in the other direction; the assembler skips it.
		if toServer {
			h.cache.AppendServerUpToLimit(st, st.ServerAsm.ack(tcp.Ack))
		} else if toClient {
			h.cache.AppendClientUpToLimit(st, st.ClientAsm.ack(tcp.Ack))
		}
	}

	if isTLSServerToClient && !st.TLSServerSeen {
		if serverInfo, ok := rules.DetectTLSServerHello(st.ServerData); ok {
			st.TLSServerSeen = true
			st.TLSServerInfo = serverInfo

			if h.debug {
				msg := fmt.Sprintf(
					"tls_server version=0x%04x cipher=0x%04x",
					serverInfo.ServerVersion,
					serverInfo.SelectedCipher,
				)

				if serverInfo.Cert != nil {
					msg += fmt.Sprintf(
						" subject=%q issuer=%q sans=%v self_signed=%t",
						serverInfo.Cert.Subject,
						serverInfo.Cert.Issuer,
						serverInfo.Cert.SANs,
						serverInfo.Cert.SelfSigned,
					)
				} else {
					msg += " cert=nil"
				}

				_ = h.eventSink.Write(Event{
					Timestamp: now,
					Type:      "TLS_SERVER_DEBUG",
					Severity:  SeverityInfo,
					Debug:     true,
					SrcIP:     srcIP,
					SrcPort:   srcPort,
					DstIP:     dstIP,
					DstPort:   dstPort,
					Message:   msg,
				})
			}
		}
	}

	var httpInfo *rules.HTTPInfo
	if isHTTPClientToServer && rules.LooksLikeHTTP(st.ClientData) {
		if hi, ok := rules.ParseHTTP(st.ClientData); ok {
			httpInfo = hi
		}
	}

	// HTTP on another port, recognised by content, is parsed for the secret
	// and media rules only (D23); identity, protocols and categories keep
	// using the standard ports.
	var contentHTTP *rules.HTTPInfo
	if httpInfo == nil && st.HTTPContent && !isHTTPClientToServer && !isTLSClientToServer && rules.LooksLikeHTTP(st.ClientData) {
		if hi, ok := rules.ParseHTTP(st.ClientData); ok {
			contentHTTP = hi
		}
	}

	// The outcome of a request is only known from the server's reply, so
	// rules about accepted requests see the request/response pair on the
	// server's packets.
	var httpExchange *rules.HTTPExchange
	if httpFlow && !fromClient && len(st.ServerData) > 0 {
		req, okReq := rules.ParseHTTP(st.ClientData)
		resp, okResp := rules.ParseHTTPResponse(st.ServerData)
		if okReq && okResp {
			httpExchange = &rules.HTTPExchange{
				Request: req, Response: resp,
				ClientIP: st.SrcIP, ServerIP: st.DstIP, ServerPort: st.DstPort,
				ServerLocal: h.isLocal(st.DstIP),
			}
		}
	}

	var mqttInfo *rules.MQTTInfo
	if isMQTTClientToServer {
		if mi, ok := rules.ParseMQTT(st.ClientData); ok {
			mqttInfo = mi
		}
	}

	var telnetInfo *rules.TelnetInfo
	if isTelnetClientToServer {
		if ti, ok := rules.ParseTelnet(st.ClientData, st.ServerData); ok {
			telnetInfo = ti
		}
	}

	if isTLSClientToServer && !st.TLSClientSeen {
		if tlsInfo, ok := rules.DetectTLSClientHello(st.ClientData); ok {
			st.TLSClientSeen = true
			st.TLSClientInfo = &tlsInfo

			if d := h.localDevice(srcIP); d != nil {
				device.EnrichFromTLS(d, tlsInfo)
				device.AddTLSBehaviorHints(d, dstPort)
				h.writeDeviceDebug(now, srcIP, d)
			}
		}
	}

	if httpInfo != nil && !st.HTTPEnriched {
		// Enrich identity once per flow: the request buffer is re-parsed on
		// every packet, and repeated enrichment inflated identity counters.
		st.HTTPEnriched = true
		if d := h.localDevice(srcIP); d != nil {
			device.EnrichFromHTTP(d, httpInfo.Headers)
			device.AddHTTPBehaviorHints(d, httpInfo, dstPort, isTLSClientToServer)
			h.writeDeviceDebug(now, srcIP, d)
		}
	}
	h.updateFlowMetadata(st, httpInfo, mqttInfo, telnetInfo)

	flowProtocols := observedProtocolsForFlow(st.DstPort, httpInfo, mqttInfo, telnetInfo, st.TLSClientSeen)
	deviceIP := h.flowDeviceIP(st)
	d := h.localDevice(deviceIP)
	if d != nil {
		observeDeviceFlow(d, now, st.DstPort, flowProtocols)
		for _, event := range h.buildDeviceNotificationEvents(now, key, deviceIP, dstIP, srcPort, dstPort, d) {
			_ = h.eventSink.Write(event)
		}
	} else {
		// Remote-to-remote traffic (e.g. a mirror port seeing transit
		// packets): analyse it, but do not create a device for it.
		d = device.NewProfile("")
	}
	if deviceIP != st.DstIP && st.ServerResponded {
		// A local server that answered is an active device too.
		if server := h.localDevice(st.DstIP); server != nil {
			server.ObserveActivity(now)
		}
	}
	h.writeFlowRecordSnapshot(now, key, st, false)

	// Rules only see the flow buffers and handshake state, so re-running
	// them on packets that changed neither (bulk transfer after the 16 KB
	// capture limit, pure ACKs) cannot produce new findings; it only cost
	// time. Rules still run on the first packet and when the server first
	// answers.
	if st.PacketCount > 1 && respondedBefore == st.ServerResponded &&
		len(st.ClientData)+len(st.ServerData) == bufferedBefore {
		h.periodicMaintenance(now)
		return
	}
	localClassification := d.Classification
	localDeviceCategory := localClassification.NormalizedCategory()
	localInferenceSource := string(localClassification.InferenceSource)
	if localInferenceSource == "" {
		localInferenceSource = string(device.InferenceSourceUnknown)
	}
	localInferenceConfidence := localClassification.ConfidenceSummary()
	localInferenceReasons := localClassification.Reasons

	flowClassification := device.Classification{
		Category:        "GenericIoT",
		InferenceSource: device.InferenceSourceUnknown,
		ConfidenceLabel: "very_low",
		Reasons:         []string{"insufficient_evidence"},
	}
	if httpInfo != nil {
		flowProfile := device.InferFlowFromHTTP(httpInfo.Headers)
		device.AddHTTPBehaviorHints(flowProfile, httpInfo, dstPort, isTLSClientToServer)
		flowClassification = flowProfile.Classification
	} else if st.TLSClientSeen && st.TLSClientInfo != nil {
		flowProfile := device.InferFlowFromTLS(*st.TLSClientInfo)
		device.AddTLSBehaviorHints(flowProfile, dstPort)
		flowClassification = flowProfile.Classification
	}
	flowDeviceCategory := flowClassification.NormalizedCategory()
	flowDeviceType := flowClassification.DeviceType
	flowInferenceSource := string(flowClassification.InferenceSource)
	if flowInferenceSource == "" {
		flowInferenceSource = string(device.InferenceSourceUnknown)
	}
	flowInferenceConfidence := flowClassification.ConfidenceSummary()
	flowInferenceReasons := flowClassification.Reasons

	deviceCategory := flowDeviceCategory
	if deviceCategory == "GenericIoT" {
		deviceCategory = localDeviceCategory
	}
	deviceInferenceSource := flowInferenceSource
	deviceInferenceConfidence := flowInferenceConfidence
	deviceInferenceReasons := flowInferenceReasons
	if deviceCategory == localDeviceCategory && flowDeviceCategory == "GenericIoT" {
		deviceInferenceSource = localInferenceSource
		deviceInferenceConfidence = localInferenceConfidence
		deviceInferenceReasons = localInferenceReasons
	}

	ctx := &rules.Context{
		NowUnix:                   now.Unix(),
		FlowKey:                   key,
		SrcIP:                     srcIP,
		SrcPort:                   srcPort,
		DstIP:                     dstIP,
		DstPort:                   dstPort,
		Payload:                   st.ClientData,
		ServerPayload:             st.ServerData,
		ServerSilent:              !st.ServerResponded,
		MACVendor:                 d.MACVendor,
		Debug:                     h.debug,
		UploadBytes:               estimateUploadBytes(httpInfo),
		HTTP:                      httpInfo,
		HTTPExchange:              httpExchange,
		MQTT:                      mqttInfo,
		Telnet:                    telnetInfo,
		TLS:                       isTLSClientToServer,
		TLSInfo:                   st.TLSClientInfo,
		TLSServerInfo:             st.TLSServerInfo,
		DeviceCategory:            deviceCategory,
		LocalDeviceCategory:       localDeviceCategory,
		FlowDeviceCategory:        flowDeviceCategory,
		CategoryCandidate:         d.Identity.CategoryCandidate,
		VendorCandidate:           d.Identity.VendorCandidate,
		FamilyCandidate:           d.Identity.FamilyCandidate,
		CategoryConfidence:        d.Identity.CategoryConfidence,
		VendorConfidence:          d.Identity.VendorConfidence,
		FamilyConfidence:          d.Identity.FamilyConfidence,
		CategoryReasons:           d.Identity.CategoryReasons,
		VendorReasons:             d.Identity.VendorReasons,
		FamilyReasons:             d.Identity.FamilyReasons,
		ObservedHosts:             mapKeys(d.Hosts),
		ObservedUserAgents:        mapKeys(d.UserAgents),
		ObservedSNIValues:         mapKeys(d.SNIValues),
		UpdateVisibility:          i4UpdateVisibility(d),
		LegacySignals:             i4LegacySignals(d),
		DeviceInferenceSource:     deviceInferenceSource,
		LocalInferenceSource:      localInferenceSource,
		FlowInferenceSource:       flowInferenceSource,
		DeviceInferenceConfidence: deviceInferenceConfidence,
		LocalInferenceConfidence:  localInferenceConfidence,
		FlowInferenceConfidence:   flowInferenceConfidence,
		DeviceInferenceReasons:    deviceInferenceReasons,
		LocalInferenceReasons:     localInferenceReasons,
		FlowInferenceReasons:      flowInferenceReasons,
		ContextClassification: inferenceView(
			deviceCategory,
			func() string {
				if deviceCategory == localDeviceCategory && flowDeviceCategory == "GenericIoT" {
					return d.DeviceType
				}
				return flowDeviceType
			}(),
			deviceInferenceSource,
			deviceInferenceConfidence,
			deviceInferenceReasons,
		),
		LocalClassification: inferenceView(
			localDeviceCategory,
			d.DeviceType,
			localInferenceSource,
			localInferenceConfidence,
			localInferenceReasons,
		),
		FlowClassification: inferenceView(
			flowDeviceCategory,
			flowDeviceType,
			flowInferenceSource,
			flowInferenceConfidence,
			flowInferenceReasons,
		),
	}
	h.annotateI6StorageObservation(ctx, d)
	h.annotateI6PIIUseObservation(ctx, d)

	if h.debug {
		summary := i6DebugSummary(
			localDeviceCategory,
			flowDeviceCategory,
			ctx.DeviceCategory,
			localInferenceSource,
			flowInferenceSource,
			deviceInferenceSource,
		)
		detail := i6DebugDetail(
			localDeviceCategory,
			flowDeviceCategory,
			ctx.DeviceCategory,
			localInferenceSource,
			flowInferenceSource,
			deviceInferenceSource,
			localInferenceConfidence,
			flowInferenceConfidence,
			deviceInferenceConfidence,
			localInferenceReasons,
			flowInferenceReasons,
			deviceInferenceReasons,
		)

		_ = h.eventSink.Write(Event{
			Timestamp: now,
			Type:      "I6_DEBUG",
			Severity:  SeverityInfo,
			Debug:     true,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Message: fmt.Sprintf(
				"summary=%q detail=%q local_device_category=%q flow_device_category=%q ctx_device_category=%q local_device_type=%q flow_device_type=%q local_inference_source=%q flow_inference_source=%q ctx_inference_source=%q local_confidence=%q flow_confidence=%q ctx_confidence=%q local_reasons=%v flow_reasons=%v ctx_reasons=%v local_classification=%+v flow_classification=%+v ctx_classification=%+v",
				summary,
				detail,
				localDeviceCategory,
				flowDeviceCategory,
				ctx.DeviceCategory,
				d.DeviceType,
				flowDeviceType,
				localInferenceSource,
				flowInferenceSource,
				deviceInferenceSource,
				localInferenceConfidence,
				flowInferenceConfidence,
				deviceInferenceConfidence,
				humanizeReasons(localInferenceReasons),
				humanizeReasons(flowInferenceReasons),
				humanizeReasons(deviceInferenceReasons),
				ctx.LocalClassification,
				ctx.FlowClassification,
				ctx.ContextClassification,
			),
		})
	}

	matches := rules.Run(ctx)
	if contentHTTP != nil {
		cctx := *ctx
		cctx.HTTP = contentHTTP
		matches = append(matches, rules.RunContentHTTP(&cctx)...)
	}
	// Later requests on a kept-alive connection reach the secret and media
	// rules too (the other rules keep looking at the first request only).
	if !isTLSClientToServer && (httpInfo != nil || contentHTTP != nil) {
		reqs := rules.ParseHTTPRequests(st.ClientData, maxRequestsPerFlow)
		for i := 1; i < len(reqs); i++ {
			cctx := *ctx
			cctx.HTTP = reqs[i]
			matches = append(matches, rules.RunContentHTTP(&cctx)...)
		}
	}

	if h.knowledge != nil {
		i6Rule := rules.NewI6PrivacyRule(h.knowledge)
		if i6Matches := i6Rule.ApplyAll(ctx); len(i6Matches) > 0 {
			matches = append(matches, i6Matches...)
		}

		i4EnrichmentRule := rules.NewI4FirmwareRiskEnrichmentRule(h.knowledge)
		if i4Matches := i4EnrichmentRule.ApplyAll(ctx); len(i4Matches) > 0 {
			matches = append(matches, i4Matches...)
		}

		i4EOLRule := rules.NewI4EOLReviewRule(h.knowledge)
		if i4Matches := i4EOLRule.ApplyAll(ctx); len(i4Matches) > 0 {
			matches = append(matches, i4Matches...)
		}

		i5, i4i5, i4i5ok := h.cachedI5(deviceIP, ctx, d)
		matches = append(matches, i5...)

		i3Rule := rules.NewI3UnexpectedCloudEndpointRule(h.knowledge)
		if i3Matches := i3Rule.ApplyAll(ctx); len(i3Matches) > 0 {
			matches = append(matches, i3Matches...)
		}

		if !st.AlreadyReported(rules.I4I5CombinedRiskRuleID) {
			if i4i5ok {
				matches = append(matches, i4i5)
			}
		}
	}

	if composite := buildCompositeRiskMatch(ctx, matches); composite != nil {
		matches = append(matches, *composite)
	}
	if quarantine := h.buildQuarantineRecommendationEvent(now, key, deviceIP, dstIP, srcPort, dstPort, d, matches); deviceIP != "" && quarantine != nil {
		_ = h.eventSink.Write(*quarantine)
		d.RecordRiskEvent(now, quarantine.Type, string(quarantine.Severity), []string{quarantine.Category})
	}

	for _, m := range matches {
		if st.AlreadyReported(m.RuleID) {
			continue
		}

		event := Event{
			Timestamp:      now,
			Type:           m.Type,
			Severity:       Severity(m.Severity),
			RuleID:         m.RuleID,
			Category:       m.Category,
			FlowKey:        key,
			Evidence:       m.Evidence,
			OWASPTags:      m.OWASPTags,
			Confidence:     m.Confidence,
			ObservedFact:   m.ObservedFact,
			Inference:      m.Inference,
			Limitation:     m.Limitation,
			Recommendation: m.Recommendation,
			Debug:          m.Debug,
			// Report findings in the flow's client -> server direction. The
			// triggering packet may be a server reply (e.g. a ServerHello
			// selecting TLS 1.0), whose addresses are reversed; downstream
			// consumers decide "external destination" from DstIP.
			SrcIP:   st.SrcIP,
			SrcPort: st.SrcPort,
			DstIP:   st.DstIP,
			DstPort: st.DstPort,
			Message: m.Message,
		}
		affected := h.affectedDeviceIP(m.Type, st)
		if key := deviceScopedKey(m, affected); key != "" {
			// A conclusion about the device itself is reported once per
			// device, not once per flow (one Echo produced >1000 identical
			// knowledge-base matches in a day of real traffic).
			if h.deviceReported[key] {
				st.MarkReported(m.RuleID)
				continue
			}
			if h.deviceReported == nil {
				h.deviceReported = map[string]bool{}
			}
			h.deviceReported[key] = true
		}
		event.DeviceKey = affected
		h.enrichEvent(&event)
		_ = h.eventSink.Write(event)

		if deviceProfile := h.localDevice(affected); deviceProfile != nil {
			deviceProfile.RecordRiskEvent(now, m.Type, string(m.Severity), m.OWASPTags)
			if isI2RiskEvent(m.Type) {
				h.updateDeviceRiskFromMatch(affected, m)
				h.writeDeviceDebug(now, affected, deviceProfile)
			}
		}

		st.MarkReported(m.RuleID)
	}

	h.periodicMaintenance(now)

	if h.debug && capturePayload && len(tcp.Payload) > 0 {
		p := tcp.Payload
		if len(p) > 256 {
			p = p[:256]
		}
		_ = h.eventSink.Write(Event{
			Timestamp: now,
			Type:      "PAYLOAD_DEBUG",
			Severity:  SeverityInfo,
			Debug:     true,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			// Never write raw payload bytes: plaintext protocols carry
			// passwords and tokens, and debug logs are easy to share.
			Message: fmt.Sprintf("payload_len=%d payload_head_hex_prefix=%x", len(tcp.Payload), p[:min(len(p), 8)]),
		})
	}
}

// periodicMaintenance sweeps idle flows and runs behaviour detectors on a
// capture-time schedule.
func (h *FlowHandler) periodicMaintenance(now time.Time) {
	if h.lastCleanup.IsZero() {
		h.lastCleanup = now
	} else if now.Sub(h.lastCleanup) >= flowCleanupInterval {
		h.lastCleanup = now
		h.cache.Cleanup(now, func(key string, st *FlowState) {
			h.finishFlow(now, key, st)
		})
	}
	if h.lastBehaviorEval.IsZero() {
		h.lastBehaviorEval = now
	} else if now.Sub(h.lastBehaviorEval) >= behaviorEvalInterval {
		h.evaluateBehavior(now)
	}

}

func (h *FlowHandler) annotateI6StorageObservation(ctx *rules.Context, d *device.DeviceProfile) {
	if h == nil || h.knowledge == nil || h.knowledge.I6StorageSignals == nil || ctx == nil || d == nil || ctx.HTTP == nil {
		return
	}

	if endpointKey := rules.I6StorageCandidateEndpointKey(ctx, h.knowledge.I6StorageSignals.Patterns); endpointKey != "" {
		ctx.StorageEndpointRepeatCount = d.ObserveStorageSignalEndpoint(endpointKey, ctx.NowUnix)
	}

	for _, fingerprint := range rules.StableIdentifierFingerprints(ctx.HTTP) {
		count := d.ObserveStableIdentifierFingerprint(fingerprint, ctx.NowUnix)
		if count > ctx.StableIdentifierRepeatCount {
			ctx.StableIdentifierRepeatCount = count
		}
	}
}

func (h *FlowHandler) annotateI6PIIUseObservation(ctx *rules.Context, d *device.DeviceProfile) {
	if ctx == nil || d == nil || ctx.HTTP == nil {
		return
	}
	host := strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"]))
	if host == "" {
		return
	}
	hits := rules.DetectPIIHits(ctx.HTTP, ctx.Payload)
	for _, piiType := range rules.PIIHitTypes(hits) {
		repeat, distinct := d.ObservePIIUseDestination(piiType, host, ctx.NowUnix)
		if repeat > ctx.PIIDestinationRepeatCount {
			ctx.PIIDestinationRepeatCount = repeat
		}
		if distinct > ctx.PIIDistinctDestinationCount {
			ctx.PIIDistinctDestinationCount = distinct
		}
	}
}

func estimateUploadBytes(httpInfo *rules.HTTPInfo) int {
	if httpInfo == nil {
		return 0
	}
	if v := strings.TrimSpace(httpInfo.Headers["content-length"]); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return len(httpInfo.Body)
}

// i5CacheEntry memoizes the device-level vulnerability-knowledge matches.
type i5CacheEntry struct {
	sig    string
	i5     []rules.Match
	i4i5   rules.Match
	i4i5ok bool
}

// cachedI5 evaluates the I5 and I4+I5 knowledge-base rules only when the
// device's identity inputs changed. Both rules depend solely on identity
// candidates and the device's observed host/UA/SNI sets, but re-running
// them per flow normalised every observed value each time, which grew
// quadratically for devices with many destinations (one UNSW day: 21 min).
func (h *FlowHandler) cachedI5(deviceIP string, ctx *rules.Context, d *device.DeviceProfile) ([]rules.Match, rules.Match, bool) {
	sig := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%d|%s|%v",
		ctx.DeviceCategory, ctx.CategoryCandidate, ctx.VendorCandidate, ctx.FamilyCandidate, ctx.FamilyConfidence, ctx.MACVendor,
		len(d.Hosts), len(d.UserAgents), len(d.SNIValues), ctx.UpdateVisibility, ctx.LegacySignals)
	if deviceIP != "" {
		if e, ok := h.i5Cache[deviceIP]; ok && e.sig == sig {
			return e.i5, e.i4i5, e.i4i5ok
		}
	}
	e := i5CacheEntry{sig: sig}
	e.i5 = rules.NewI5KnownVulnerableComponentRule(h.knowledge).ApplyAll(ctx)
	e.i4i5, e.i4i5ok = rules.NewI4I5CombinedRiskRule(h.knowledge).Apply(ctx)
	if deviceIP != "" {
		if h.i5Cache == nil {
			h.i5Cache = map[string]i5CacheEntry{}
		}
		h.i5Cache[deviceIP] = e
	}
	return e.i5, e.i4i5, e.i4i5ok
}

// maxRequestsPerFlow bounds how many requests of one kept-alive connection
// are parsed for the secret and media rules.
const maxRequestsPerFlow = 16

// isStartTLSRequest reports a client command that upgrades the session to
// TLS: XMPP <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/> (RFC 6120),
// SMTP and IMAP STARTTLS (RFC 3207, 9051), POP3 STLS (RFC 2595) and FTP
// AUTH TLS/SSL (RFC 4217).
func isStartTLSRequest(p []byte) bool {
	low := bytes.ToLower(bytes.TrimLeft(p, " \t\r\n"))
	switch {
	case bytes.Contains(low, []byte("<starttls")) && bytes.Contains(low, []byte("urn:ietf:params:xml:ns:xmpp-tls")):
		return true
	case bytes.HasPrefix(low, []byte("starttls")), bytes.HasPrefix(low, []byte("stls")),
		bytes.HasPrefix(low, []byte("auth tls")), bytes.HasPrefix(low, []byte("auth ssl")):
		return true
	}
	// IMAP: a tagged command, "a1 STARTTLS"
	if sp := bytes.IndexByte(low, ' '); sp > 0 && sp < 16 && bytes.HasPrefix(low[sp+1:], []byte("starttls")) {
		return true
	}
	return false
}

// looksLikeTLSRecord reports whether a stream starts with a TLS handshake
// record carrying a ClientHello. Some stacks send the 5-byte record header in
// a segment of its own (E11: a blood-pressure meter on port 8777); the header
// alone counts when its version and length are those of a handshake record.
func looksLikeTLSRecord(payload []byte) bool {
	if len(payload) < 5 || payload[0] != 22 || payload[1] != 3 || payload[2] > 4 {
		return false
	}
	if len(payload) == 5 {
		n := int(payload[3])<<8 | int(payload[4])
		return n >= 40 && n <= 16384
	}
	return payload[5] == 1
}

// ImportIdentityState loads per-MAC self-descriptions saved by an earlier
// capture (device.IdentityState). Call it before the first packet.
func (h *FlowHandler) ImportIdentityState(state device.IdentityState) {
	if h == nil || h.devices == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.devices.ImportIdentityState(state)
}

// ExportIdentityState returns the per-MAC self-descriptions to save for the
// next capture.
func (h *FlowHandler) ExportIdentityState() device.IdentityState {
	if h == nil || h.devices == nil {
		return device.IdentityState{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.devices.ExportIdentityState()
}
