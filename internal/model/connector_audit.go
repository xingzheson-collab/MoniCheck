package model

import "time"

type ConnectorAuditEvent struct {
	ID          string            `json:"id"`
	ConnectorID string            `json:"connector_id"`
	Action      string            `json:"action"`
	Field       string            `json:"field"`
	Status      string            `json:"status"`
	Message     string            `json:"message,omitempty"`
	RequestID   string            `json:"request_id,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}
