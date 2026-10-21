package device

import (
	"sort"
)

func addScore(scores map[string]float64, key string, delta float64) {
	if key == "" || delta <= 0 {
		return
	}
	scores[key] += delta
}

func bestScoredLabel(scores map[string]float64, prefer string) (string, float64) {
	bestLabel := ""
	bestScore := 0.0

	labels := make([]string, 0, len(scores))
	for label := range scores {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	for _, label := range labels {
		score := scores[label]
		if score > bestScore || (score == bestScore && label == prefer) {
			bestLabel = label
			bestScore = score
		}
	}

	return bestLabel, bestScore
}

func EnrichFromHTTP(d *DeviceProfile, headers map[string]string) {
	if host, ok := headers["host"]; ok {
		d.Hosts[host] = true
		d.noteObserved("host", host)
		d.ObserveIdentitySignal("host", host, 0)
		d.Evidence = appendUnique(d.Evidence, "Host="+host)
	}

	if ua, ok := headers["user-agent"]; ok {
		d.UserAgents[ua] = true
		d.noteObserved("ua", ua)
		d.ObserveIdentitySignal("ua", ua, 0)
		d.Evidence = appendUnique(d.Evidence, "UA="+ua)
	}

	if srv, ok := headers["server"]; ok {
		d.Servers[srv] = true
		d.noteObserved("server", srv)
		d.ObserveIdentitySignal("server", srv, 0)
		d.Evidence = appendUnique(d.Evidence, "Server="+srv)
	}

	recomputeDeviceIdentity(d)
}

func InferFlowFromHTTP(headers map[string]string) *DeviceProfile {
	d := NewProfile("")
	EnrichFromHTTP(d, headers)
	return d
}
