package model

import "time"

type APIAccessAuditEvent struct {
	ID             string    `json:"id"`
	RequestID      string    `json:"request_id"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Query          string    `json:"query,omitempty"`
	StatusCode     int       `json:"status_code"`
	DurationMillis int64     `json:"duration_millis"`
	RemoteAddr     string    `json:"remote_addr,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	Authenticated  bool      `json:"authenticated"`
	CreatedAt      time.Time `json:"created_at"`
}
