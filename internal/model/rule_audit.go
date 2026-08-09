package model

import "time"

type RuleAuditEvent struct {
	ID           string            `json:"id"`
	Action       string            `json:"action"`
	Status       string            `json:"status"`
	RuleID       string            `json:"rule_id,omitempty"`
	RuleCount    int               `json:"rule_count,omitempty"`
	MatchedCount int               `json:"matched_count,omitempty"`
	Message      string            `json:"message,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}
