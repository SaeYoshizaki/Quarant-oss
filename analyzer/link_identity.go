package analyzer

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"quarant/analyzer/device"
	"quarant/analyzer/discovery"
)

// macChangeReportInterval rate-limits IP_MAC_BINDING_CHANGED per IP and
// MAC pair.
const macChangeReportInterval = 10 * time.Minute

// pendingDHCPLimit bounds DHCP hints held for MACs whose IP is not known yet.
const pendingDHCPLimit = 1024

type pendingDHCP struct {
	at   time.Time
	info discovery.DHCPClientInfo
}

// observeLinkLayer binds MAC addresses to local IPs from Ethernet and ARP
// headers. It only trusts the source MAC of frames whose source IP is local:
// for routed traffic the source MAC is the router's, not the remote host's.
func (h *FlowHandler) observeLinkLayer(packet gopacket.Packet, now time.Time, srcIP string) {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.AddrType == layers.LinkTypeEthernet && len(arp.SourceProtAddress) == 4 {
			ip := net.IP(arp.SourceProtAddress).String()
			h.bindMAC(now, ip, net.HardwareAddr(arp.SourceHwAddress), "arp")
		}
		return
	}
	if srcIP == "" {
		return
	}
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		h.bindMAC(now, srcIP, ethLayer.(*layers.Ethernet).SrcMAC, "ethernet")
		return
	}
	// Linux cooked captures (e.g. the Deakin IoT dataset) carry the
	// sender's link address only.
	if sllLayer := packet.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
		sll := sllLayer.(*layers.LinuxSLL)
		if sll.AddrLen == 6 {
			h.bindMAC(now, srcIP, net.HardwareAddr(sll.Addr), "linux_sll")
		}
	}
}

func (h *FlowHandler) bindMAC(now time.Time, ip string, mac net.HardwareAddr, source string) {
	d := h.localDevice(ip)
	if d == nil || len(mac) != 6 {
		return
	}
	info := discovery.LookupMAC(mac)
	if info.Multicast {
		return
	}
	// Report every switch of the binding (rate-limited per MAC pair), not
	// only the first appearance of a new MAC: ARP spoofing flips an
	// address back and forth between the genuine and the attacker MAC.
	if d.CurrentMAC != "" && d.CurrentMAC != info.MAC {
		pair := ip + "|" + d.CurrentMAC + "|" + info.MAC
		if last, ok := h.macChangeReported[pair]; !ok || now.Sub(last) >= macChangeReportInterval {
			if h.macChangeReported == nil {
				h.macChangeReported = map[string]time.Time{}
			}
			h.macChangeReported[pair] = now
			h.reportMACChange(now, ip, d.CurrentMAC, info.MAC, source)
		}
	}
	d.CurrentMAC = info.MAC
	d.ObserveMAC(info.MAC)
	h.devices.LinkMAC(d, info.MAC)
	d.AddIdentityEvidence(now, "mac", info.MAC, string(discovery.BasisObserved), source)
	if info.LocallyAdministered {
		d.AddIdentityEvidence(now, "mac_locally_administered", "true", string(discovery.BasisObserved), "ethernet")
	} else if info.Vendor != "" {
		d.AddIdentityEvidence(now, "mac_vendor", info.Vendor, string(discovery.BasisReference), "oui_registry")
		if d.MACVendor == "" {
			d.MACVendor = info.Vendor
		}
	}
	if h.macToIP == nil {
		h.macToIP = map[string]string{}
	}
	h.macToIP[info.MAC] = ip
	if pending, ok := h.pendingDHCP[info.MAC]; ok {
		delete(h.pendingDHCP, info.MAC)
		h.applyDHCP(pending.at, d, pending.info)
	}
}

// observeDiscovery handles UDP identity sources: DHCP client options, mDNS
// announcements, SSDP headers and the device's own DNS queries.
func (h *FlowHandler) observeDiscovery(packet gopacket.Packet, now time.Time, srcIP string, udp *layers.UDP, dns *layers.DNS) {
	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		if info, ok := discovery.ParseDHCPClient(dhcpLayer.(*layers.DHCPv4)); ok {
			h.observeDHCP(now, info)
		}
		return
	}
	d := h.localDevice(srcIP)
	if d == nil {
		return
	}
	switch {
	case dns != nil && (udp.SrcPort == 5353 || udp.DstPort == 5353):
		if info, ok := discovery.ParseMDNSAnnouncement(dns); ok {
			for _, v := range info.Services {
				d.AddIdentityEvidence(now, "mdns_service", v, string(discovery.BasisObserved), "mdns")
			}
			for _, v := range info.Instances {
				d.AddIdentityEvidence(now, "mdns_instance", v, string(discovery.BasisObserved), "mdns")
			}
			for _, v := range info.Hostnames {
				d.AddIdentityEvidence(now, "hostname", strings.TrimSuffix(v, ".local"), string(discovery.BasisObserved), "mdns")
			}
			for _, v := range info.TXT {
				d.AddIdentityEvidence(now, "mdns_txt", v, string(discovery.BasisObserved), "mdns")
			}
		}
	case dns != nil && udp.DstPort == 53 && !dns.QR:
		for _, q := range dns.Questions {
			d.ObserveDNSQuery(string(q.Name))
		}
	case udp.SrcPort == 1900 || udp.DstPort == 1900:
		if info, ok := discovery.ParseSSDP(udp.Payload); ok {
			attr := "ssdp_server"
			if info.Kind == "search" {
				attr = "ssdp_search_agent"
			}
			d.AddIdentityEvidence(now, attr, info.Server, string(discovery.BasisObserved), "ssdp")
			if info.Kind != "search" {
				d.AddIdentityEvidence(now, "ssdp_location", info.Location, string(discovery.BasisObserved), "ssdp")
				// The UPnP device type the device announces (NT or USN of a
				// NOTIFY / search response), e.g. urn:schemas-upnp-org:device:Printer:1.
				for _, v := range []string{info.Target, info.USN} {
					if t := discovery.UPnPDeviceType(v); t != "" {
						d.AddIdentityEvidence(now, "ssdp_device_type", t, string(discovery.BasisObserved), "ssdp")
					}
				}
			}
		}
	}
}

func (h *FlowHandler) observeDHCP(now time.Time, info discovery.DHCPClientInfo) {
	mac := strings.ToLower(info.ClientMAC.String())
	ip := ""
	if info.ClientIP != nil {
		ip = info.ClientIP.String()
	} else if known, ok := h.macToIP[mac]; ok {
		ip = known
	}
	if d := h.localDevice(ip); d != nil {
		h.bindMAC(now, ip, info.ClientMAC, "dhcp")
		h.applyDHCP(now, d, info)
		return
	}
	// DISCOVER without a requested IP: keep the hints until the MAC is seen
	// with an address.
	if h.pendingDHCP == nil {
		h.pendingDHCP = map[string]pendingDHCP{}
	}
	if _, ok := h.pendingDHCP[mac]; ok || len(h.pendingDHCP) < pendingDHCPLimit {
		h.pendingDHCP[mac] = pendingDHCP{at: now, info: info}
	}
}

func (h *FlowHandler) applyDHCP(now time.Time, d *device.DeviceProfile, info discovery.DHCPClientInfo) {
	d.ObserveActivity(now)
	d.AddIdentityEvidence(now, "hostname", info.Hostname, string(discovery.BasisObserved), "dhcp")
	d.AddIdentityEvidence(now, "dhcp_vendor_class", info.VendorClass, string(discovery.BasisObserved), "dhcp")
	d.AddIdentityEvidence(now, "dhcp_param_request_list", info.ParamRequestList, string(discovery.BasisObserved), "dhcp")
}

// observeUDPActivity records UDP usage (DNS, NTP, QUIC, ...) on the local
// sender's profile so the inventory is not TCP-only.
func (h *FlowHandler) observeUDPActivity(now time.Time, srcIP, dstIP string, srcPort, dstPort uint16, dns *layers.DNS) {
	d := h.localDevice(srcIP)
	if d == nil {
		return
	}
	protocols := []string{"udp"}
	if app := udpAppProtocol(srcPort, dstPort, dns); app != "" {
		protocols = append(protocols, app)
	}
	port := dstPort
	if h.isLocal(dstIP) && srcPort < dstPort && srcPort != 0 {
		// A local reply from a well-known port (e.g. a DNS server on the
		// LAN answering): the service port is the source port.
		port = srcPort
	}
	observeDeviceFlow(d, now, port, protocols)
}

func decodeDNS(payload []byte) *layers.DNS {
	if len(payload) < 12 {
		return nil
	}
	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	return dns
}

// reportMACChange records that an IP address was claimed by a second MAC.
func (h *FlowHandler) reportMACChange(now time.Time, ip, oldMAC, newMAC, source string) {
	event := Event{
		Timestamp:      now,
		Type:           "IP_MAC_BINDING_CHANGED",
		Severity:       SeverityWarning,
		RuleID:         "IP_MAC_BINDING_CHANGED",
		Category:       "L2",
		Confidence:     "high",
		Basis:          BasisObserved,
		DeviceKey:      ip,
		SrcIP:          ip,
		Evidence:       fmt.Sprintf("ip=%s previous_mac=%s new_mac=%s source=%s", ip, oldMAC, newMAC, source),
		ObservedFact:   fmt.Sprintf("%s was seen with MAC %s after previously using %s.", ip, newMAC, oldMAC),
		Inference:      "The address moved to another interface. This happens with DHCP reassignment, Wi-Fi repeaters and MAC randomization, but is also the visible effect of ARP spoofing (man-in-the-middle).",
		Limitation:     "Passive monitoring cannot tell legitimate reassignment from spoofing on its own; check whether both MACs belong to known devices and whether the change repeats.",
		Recommendation: "Identify both MAC addresses. Repeated alternation, or a MAC belonging to another device, warrants investigation.",
		Message:        "IP-to-MAC binding changed.",
	}
	h.enrichEvent(&event)
	_ = h.eventSink.Write(event)
}
