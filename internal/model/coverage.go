package model

import "time"

type CoverageSignal string

const (
	CoverageSignalMetrics    CoverageSignal = "metrics"
	CoverageSignalLogs       CoverageSignal = "logs"
	CoverageSignalDashboards CoverageSignal = "dashboards"
	CoverageSignalAlerts     CoverageSignal = "alerts"
	CoverageSignalTraces     CoverageSignal = "traces"
	CoverageSignalProfiles   CoverageSignal = "profiles"
)

type CoverageExpectationScope string

const (
	CoverageScopeAllServices CoverageExpectationScope = "ALL_SERVICES"
	CoverageScopeService     CoverageExpectationScope = "SERVICE"
	CoverageScopeNamespace   CoverageExpectationScope = "NAMESPACE"
	CoverageScopeLabel       CoverageExpectationScope = "LABEL_SELECTOR"
)

const BuiltinServiceCoverageExpectationID = "builtin.service-baseline"

type CoverageExpectation struct {
	ID              string                   `json:"id"`
	Name            string                   `json:"name"`
	Scope           CoverageExpectationScope `json:"scope"`
	ScopeValue      string                   `json:"scope_value,omitempty"`
	RequiredSignals []CoverageSignal         `json:"required_signals"`
	Owner           string                   `json:"owner"`
	Rationale       string                   `json:"rationale"`
	Enabled         bool                     `json:"enabled"`
	CreatedBy       string                   `json:"created_by"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedBy       string                   `json:"updated_by,omitempty"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

func BuiltinServiceCoverageExpectation() CoverageExpectation {
	return CoverageExpectation{
		ID:              BuiltinServiceCoverageExpectationID,
		Name:            "Service baseline",
		Scope:           CoverageScopeAllServices,
		RequiredSignals: []CoverageSignal{CoverageSignalMetrics, CoverageSignalDashboards, CoverageSignalAlerts},
		Owner:           "platform",
		Rationale:       "Active services should have metric, dashboard, and alert coverage when those inventories are evaluable.",
		Enabled:         true,
		CreatedBy:       "monicheck",
	}
}

type CoverageExceptionState string

const (
	CoverageExceptionActive  CoverageExceptionState = "ACTIVE"
	CoverageExceptionExpired CoverageExceptionState = "EXPIRED"
	CoverageExceptionRevoked CoverageExceptionState = "REVOKED"
)

type CoverageException struct {
	ID               string         `json:"id"`
	ExpectationID    string         `json:"expectation_id"`
	ServiceID        string         `json:"service_id"`
	Signal           CoverageSignal `json:"signal"`
	Owner            string         `json:"owner"`
	Reason           string         `json:"reason"`
	CreatedBy        string         `json:"created_by"`
	CreatedAt        time.Time      `json:"created_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
	RevokedAt        *time.Time     `json:"revoked_at,omitempty"`
	RevokedBy        string         `json:"revoked_by,omitempty"`
	RevocationReason string         `json:"revocation_reason,omitempty"`
}

func (e CoverageException) State(now time.Time) CoverageExceptionState {
	if e.RevokedAt != nil {
		return CoverageExceptionRevoked
	}
	if !e.ExpiresAt.After(now) {
		return CoverageExceptionExpired
	}
	return CoverageExceptionActive
}

type CoverageExceptionView struct {
	CoverageException
	State CoverageExceptionState `json:"state"`
}
