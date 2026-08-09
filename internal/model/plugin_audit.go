package model

import "time"

type PluginAuditEvent struct {
	ID             string            `json:"id"`
	PluginID       string            `json:"plugin_id"`
	PluginType     string            `json:"plugin_type"`
	Action         string            `json:"action"`
	Status         string            `json:"status"`
	DurationMillis int64             `json:"duration_millis,omitempty"`
	Message        string            `json:"message,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}
