package model

import "time"

type FindingOccurrence struct {
	FindingID        string          `json:"finding_id"`
	GroupKey         string          `json:"group_key"`
	AnalyzerID       string          `json:"analyzer_id"`
	FindingType      string          `json:"finding_type"`
	Severity         Severity        `json:"severity"`
	Category         FindingCategory `json:"category"`
	ResourceType     ResourceType    `json:"resource_type"`
	FirstSeenAt      time.Time       `json:"first_seen_at"`
	LastSeenAt       time.Time       `json:"last_seen_at"`
	ObservationCount int             `json:"observation_count"`
	ReopenCount      int             `json:"reopen_count"`
	Active           bool            `json:"active"`
	ResolvedAt       *time.Time      `json:"resolved_at,omitempty"`
}
