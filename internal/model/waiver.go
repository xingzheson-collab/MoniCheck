package model

import "time"

type WaiverScope string

const (
	WaiverScopeFinding     WaiverScope = "FINDING"
	WaiverScopeResource    WaiverScope = "RESOURCE"
	WaiverScopeAnalyzer    WaiverScope = "ANALYZER"
	WaiverScopeFindingType WaiverScope = "FINDING_TYPE"
)

type WaiverState string

const (
	WaiverStateActive  WaiverState = "ACTIVE"
	WaiverStateExpired WaiverState = "EXPIRED"
	WaiverStateRevoked WaiverState = "REVOKED"
)

type Waiver struct {
	ID               string      `json:"id"`
	Scope            WaiverScope `json:"scope"`
	ScopeValue       string      `json:"scope_value"`
	Owner            string      `json:"owner"`
	Reason           string      `json:"reason"`
	CreatedBy        string      `json:"created_by"`
	CreatedAt        time.Time   `json:"created_at"`
	ExpiresAt        time.Time   `json:"expires_at"`
	RevokedAt        *time.Time  `json:"revoked_at,omitempty"`
	RevokedBy        string      `json:"revoked_by,omitempty"`
	RevocationReason string      `json:"revocation_reason,omitempty"`
}

func (w Waiver) State(now time.Time) WaiverState {
	if w.RevokedAt != nil {
		return WaiverStateRevoked
	}
	if !w.ExpiresAt.After(now) {
		return WaiverStateExpired
	}
	return WaiverStateActive
}

type WaiverView struct {
	Waiver
	State WaiverState `json:"state"`
}
