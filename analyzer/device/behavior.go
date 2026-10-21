package device

import (
	"strings"

	"quarant/analyzer/rules"
)

func AddHTTPBehaviorHints(d *DeviceProfile, http *rules.HTTPInfo, dstPort uint16, tls bool) {
	if d == nil {
		return
	}
	if d.Paths == nil {
		d.Paths = map[string]bool{}
	}
	if d.Ports == nil {
		d.Ports = map[uint16]bool{}
	}
	if d.Protocols == nil {
		d.Protocols = map[string]bool{}
	}

	if http != nil {
		path := strings.TrimSpace(http.Path)
		if path != "" {
			d.Paths[path] = true
			d.noteObserved("path", path)
			d.ObserveIdentitySignal("path", path, 0)
			d.Evidence = appendUnique(d.Evidence, "Path="+path)
		}
	}

	d.Ports[dstPort] = true
	if tls {
		d.Protocols["https"] = true
		d.Protocols["tls"] = true
	} else {
		d.Protocols["http"] = true
	}

	switch dstPort {
	case 554:
		d.Protocols["rtsp"] = true
	case 1883:
		d.Protocols["mqtt"] = true
	case 8883:
		d.Protocols["mqtt"] = true
		d.Protocols["tls"] = true
	case 5683:
		d.Protocols["coap"] = true
	}

	recomputeDeviceIdentity(d)
}

func AddTLSBehaviorHints(d *DeviceProfile, dstPort uint16) {
	if d == nil {
		return
	}
	if d.Ports == nil {
		d.Ports = map[uint16]bool{}
	}
	if d.Protocols == nil {
		d.Protocols = map[string]bool{}
	}

	d.Ports[dstPort] = true
	d.Protocols["tls"] = true
	d.Protocols["https"] = true

	switch dstPort {
	case 8883:
		d.Protocols["mqtt"] = true
	case 5683:
		d.Protocols["coap"] = true
	case 554:
		d.Protocols["rtsp"] = true
	}

	recomputeDeviceIdentity(d)
}
