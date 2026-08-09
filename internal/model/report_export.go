package model

import "time"

type ReportExport struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Format      string    `json:"format"`
	Origin      string    `json:"origin,omitempty"`
	ExecutionID string    `json:"execution_id,omitempty"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	Content     string    `json:"content"`
	CreatedAt   time.Time `json:"created_at"`
}
