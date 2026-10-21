package device

import "time"

const (
	ObservationWindowSeconds = 30 * 60
	MaxObservationKeys       = 128
)

type ObservationCounter struct {
	Count    int
	LastSeen int64
}

type DeviceProfile struct {
	IP string

	FirstSeen time.Time
	LastSeen  time.Time

	Hosts      map[string]bool
	UserAgents map[string]bool
	Servers    map[string]bool
	SNIValues  map[string]bool
	Paths      map[string]bool
	Ports      map[uint16]bool
	Protocols  map[string]bool

	DeviceType string
	Vendor     string
	Model      string

	Confidence   float64
	Evidence     []string
	TypeScores   map[string]float64
	VendorScores map[string]float64
	FamilyScores map[string]float64

	Classification  Classification
	KnownDeviceType string
	KnownConfidence float64
	Identity        DeviceIdentity

	JA3 string

	// Link-layer and discovery identity (see identity_hints.go).
	MAC           string
	MACVendor     string // IEEE OUI vendor of MAC; empty if unknown/randomized
	CurrentMAC    string // MAC most recently seen for this IP
	MACs          map[string]bool
	IdentityHints map[string]*identityHint
	DNSQueries    map[string]bool
	linked        *linkedIdentity // self-descriptions shared by MAC (linked.go)

	IdentitySignalObservations map[string]ObservationCounter
	NotificationObservations   map[string]ObservationCounter

	ObservedServices map[string]bool
	InsecureServices map[string]bool

	StorageSignalEndpoints       map[string]ObservationCounter
	StableIdentifierFingerprints map[string]ObservationCounter
	PIIUseDestinations           map[string]ObservationCounter

	AdminSuspected            bool
	ExternalExposureSuspected bool

	RiskReasons map[string]bool
	RiskScore   int

	RiskEventCount    int
	SeverityCounts    map[string]int
	OWASPTagCounts    map[string]int
	LastRiskEventType string
	LastRiskEventAt   time.Time

	// observed indexes Hosts, Paths, UserAgents, Servers and SNIValues for
	// keyword matching (observed_index.go).
	observed map[string]*observedIndex
}

func (p *DeviceProfile) AddObservedService(service string) {
	if service == "" {
		return
	}
	if p.ObservedServices == nil {
		p.ObservedServices = make(map[string]bool)
	}
	p.ObservedServices[service] = true
}

func (p *DeviceProfile) AddInsecureService(service string) {
	if service == "" {
		return
	}
	if p.InsecureServices == nil {
		p.InsecureServices = make(map[string]bool)
	}
	p.InsecureServices[service] = true
}

func (p *DeviceProfile) AddRiskReason(reason string) {
	if reason == "" {
		return
	}
	if p.RiskReasons == nil {
		p.RiskReasons = make(map[string]bool)
	}
	p.RiskReasons[reason] = true
}

func (p *DeviceProfile) ObserveStorageSignalEndpoint(endpoint string, nowUnix int64) int {
	if endpoint == "" {
		return 0
	}
	if p.StorageSignalEndpoints == nil {
		p.StorageSignalEndpoints = make(map[string]ObservationCounter)
	}
	return observeWithinWindow(p.StorageSignalEndpoints, endpoint, nowUnix)
}

func (p *DeviceProfile) ObserveStableIdentifierFingerprint(fingerprint string, nowUnix int64) int {
	if fingerprint == "" {
		return 0
	}
	if p.StableIdentifierFingerprints == nil {
		p.StableIdentifierFingerprints = make(map[string]ObservationCounter)
	}
	return observeWithinWindow(p.StableIdentifierFingerprints, fingerprint, nowUnix)
}

func (p *DeviceProfile) ObservePIIUseDestination(piiType, host string, nowUnix int64) (int, int) {
	if piiType == "" || host == "" {
		return 0, 0
	}
	if p.PIIUseDestinations == nil {
		p.PIIUseDestinations = make(map[string]ObservationCounter)
	}
	key := piiType + "|" + host
	repeat := observeWithinWindow(p.PIIUseDestinations, key, nowUnix)

	distinct := 0
	prefix := piiType + "|"
	for observed, counter := range p.PIIUseDestinations {
		if observationExpired(counter, nowUnix) {
			continue
		}
		if len(observed) >= len(prefix) && observed[:len(prefix)] == prefix {
			distinct++
		}
	}

	return repeat, distinct
}

func (p *DeviceProfile) ObserveIdentitySignal(kind, value string, nowUnix int64) int {
	if kind == "" || value == "" {
		return 0
	}
	if p.IdentitySignalObservations == nil {
		p.IdentitySignalObservations = make(map[string]ObservationCounter)
	}
	if nowUnix == 0 {
		nowUnix = 1
	}
	return observeWithinWindow(p.IdentitySignalObservations, kind+"|"+value, nowUnix)
}

func (p *DeviceProfile) ObserveNotification(name string, nowUnix int64) int {
	if p == nil || name == "" {
		return 0
	}
	if p.NotificationObservations == nil {
		p.NotificationObservations = make(map[string]ObservationCounter)
	}
	return observeWithinWindow(p.NotificationObservations, name, nowUnix)
}

func (p *DeviceProfile) IdentitySignalRepeatCount(kind, value string) int {
	if p == nil || p.IdentitySignalObservations == nil || kind == "" || value == "" {
		return 0
	}
	return p.IdentitySignalObservations[kind+"|"+value].Count
}

func observeWithinWindow(observations map[string]ObservationCounter, key string, nowUnix int64) int {
	pruneObservationCounters(observations, nowUnix)

	counter := observations[key]
	if observationExpired(counter, nowUnix) {
		counter = ObservationCounter{}
	}
	counter.Count++
	counter.LastSeen = nowUnix
	observations[key] = counter
	return counter.Count
}

func pruneObservationCounters(observations map[string]ObservationCounter, nowUnix int64) {
	for key, counter := range observations {
		if observationExpired(counter, nowUnix) {
			delete(observations, key)
		}
	}
	if len(observations) < MaxObservationKeys {
		return
	}
	for len(observations) >= MaxObservationKeys {
		oldestKey := ""
		oldestSeen := int64(0)
		for key, counter := range observations {
			if oldestKey == "" || counter.LastSeen < oldestSeen {
				oldestKey = key
				oldestSeen = counter.LastSeen
			}
		}
		if oldestKey == "" {
			return
		}
		delete(observations, oldestKey)
	}
}

func observationExpired(counter ObservationCounter, nowUnix int64) bool {
	if counter.LastSeen == 0 {
		return true
	}
	if nowUnix == 0 {
		return false
	}
	return nowUnix-counter.LastSeen > ObservationWindowSeconds
}

func (p *DeviceProfile) MarkAdminSuspected() {
	p.AdminSuspected = true
}

func (p *DeviceProfile) MarkExternalExposure() {
	p.ExternalExposureSuspected = true
}

func (p *DeviceProfile) RecalculateRiskScore() {
	score := 0

	if p.InsecureServices["telnet"] {
		score += 40
	}
	if p.InsecureServices["ftp"] {
		score += 30
	}
	if p.InsecureServices["mqtt"] {
		score += 20
	}
	if p.InsecureServices["rtsp"] {
		score += 20
	}
	if p.InsecureServices["coap"] {
		score += 20
	}
	if p.AdminSuspected {
		score += 25
	}
	if p.ExternalExposureSuspected {
		score += 30
	}
	if score > 100 {
		score = 100
	}

	p.RiskScore = score
}
