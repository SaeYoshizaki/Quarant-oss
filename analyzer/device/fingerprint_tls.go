package device

import "quarant/analyzer/rules"

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func EnrichFromTLS(d *DeviceProfile, info rules.TLSClientHelloInfo) {
	if d.SNIValues == nil {
		d.SNIValues = map[string]bool{}
	}

	if info.SNI != "" {
		d.SNIValues[info.SNI] = true
		d.noteObserved("sni", info.SNI)
		d.ObserveIdentitySignal("sni", info.SNI, 0)
		d.Evidence = appendUnique(d.Evidence, "SNI="+info.SNI)
	}

	ja3 := rules.BuildJA3Hash(info)
	if ja3 != "" {
		d.JA3 = ja3
		d.ObserveIdentitySignal("ja3", ja3, 0)
		d.Evidence = appendUnique(d.Evidence, "JA3="+ja3)
	}

	recomputeDeviceIdentity(d)
}

func InferFlowFromTLS(info rules.TLSClientHelloInfo) *DeviceProfile {
	d := NewProfile("")
	EnrichFromTLS(d, info)
	return d
}
