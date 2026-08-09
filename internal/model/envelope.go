package model

import "time"

type ResponseEnvelope struct {
	Data  any           `json:"data,omitempty"`
	Error *ErrorPayload `json:"error"`
	Meta  Meta          `json:"meta"`
}

type Meta struct {
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}
