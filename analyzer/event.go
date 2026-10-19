package analyzer

import "time"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  Severity  `json:"severity"`

	RuleID                  string       `json:"rule_id,omitempty"`
	Category                string       `json:"category,omitempty"`
	FlowKey                 string       `json:"flow_key,omitempty"`
	Evidence                string       `json:"evidence,omitempty"`
	OWASPTags               []string     `json:"owasp_tags,omitempty"`
	Confidence              string       `json:"confidence,omitempty"`
	Basis                   string       `json:"basis,omitempty"`
	ObservedFact            string       `json:"observed_fact,omitempty"`
	Inference               string       `json:"inference,omitempty"`
	Limitation              string       `json:"limitation,omitempty"`
	Recommendation          string       `json:"recommendation,omitempty"`
	UserTitle               string       `json:"user_title,omitempty"`
	UserMessage             string       `json:"user_message,omitempty"`
	UserImpact              string       `json:"user_impact,omitempty"`
	ActionIDs               []string     `json:"action_ids,omitempty"`
	UserActions             []UserAction `json:"user_actions,omitempty"`
	RecommendedAction       string       `json:"recommended_action,omitempty"`
	DryRun                  bool         `json:"dry_run,omitempty"`
	SuggestedFirewallAction string       `json:"suggested_firewall_action,omitempty"`
	DeviceKey               string       `json:"device_key,omitempty"`
	DeviceLabel             string       `json:"device_label,omitempty"`
	DeviceStatus            string       `json:"device_status,omitempty"`
	Debug                   bool         `json:"debug,omitempty"`
	// Source names the analyser that produced the event when it is not
	// Quarant's own parser (e.g. "zeek").
	Source string `json:"source,omitempty"`
	// Sources lists every analyser that reported the finding on this
	// connection, after the outputs are overlaid (internal/corroborate).
	Sources []string `json:"sources,omitempty"`

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	Message string `json:"message,omitempty"`
}

type UserAction struct {
	ID          string `json:"id,omitempty"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Difficulty  string `json:"difficulty,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	Fallback    string `json:"fallback,omitempty"`
}
