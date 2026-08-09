package model

import "time"

type ExecutionStatus string

const (
	ExecutionStatusSucceeded ExecutionStatus = "SUCCEEDED"
	ExecutionStatusWarning   ExecutionStatus = "WARNING"
	ExecutionStatusFailed    ExecutionStatus = "FAILED"
)

type ExecutionResult struct {
	ID           string          `json:"id"`
	Status       ExecutionStatus `json:"status"`
	AnalyzerIDs  []string        `json:"analyzer_ids"`
	FindingCount int             `json:"finding_count"`
	StartedAt    time.Time       `json:"started_at"`
	FinishedAt   time.Time       `json:"finished_at"`
	Error        string          `json:"error,omitempty"`
}

type ConnectorStatus struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	Status               ExecutionStatus `json:"status"`
	ResourceCount        int             `json:"resource_count"`
	RelationshipCount    int             `json:"relationship_count"`
	OrphanedCount        int             `json:"orphaned_resource_count,omitempty"`
	RemovedRelationCount int             `json:"removed_relationship_count,omitempty"`
	LastStartedAt        time.Time       `json:"last_started_at"`
	LastFinishedAt       time.Time       `json:"last_finished_at"`
	DurationMillis       int64           `json:"duration_millis"`
	Error                string          `json:"error,omitempty"`
	Diagnostics          []Diagnostic    `json:"diagnostics,omitempty"`
}

type Diagnostic struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Status            ExecutionStatus   `json:"status"`
	Message           string            `json:"message"`
	ResourceCount     int               `json:"resource_count,omitempty"`
	RelationshipCount int               `json:"relationship_count,omitempty"`
	DurationMillis    int64             `json:"duration_millis,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}
