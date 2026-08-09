package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const ContractVersion = "evidence-bundle.v1"

type Bundle struct {
	ContractVersion string              `json:"contract_version"`
	BundleID        string              `json:"bundle_id"`
	GeneratedAt     time.Time           `json:"generated_at"`
	Product         Product             `json:"product"`
	Execution       Execution           `json:"execution"`
	Summary         Summary             `json:"summary"`
	Coverage        Coverage            `json:"coverage"`
	Cost            Cost                `json:"cost"`
	Connectors      []ConnectorEvidence `json:"connectors"`
	Findings        []FindingEvidence   `json:"findings"`
}

type Product struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type Execution struct {
	Ref           string    `json:"ref"`
	Status        string    `json:"status"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	AnalyzerCount int       `json:"analyzer_count"`
}

type Summary struct {
	ResourceCount    int `json:"resource_count"`
	FindingCount     int `json:"finding_count"`
	OpenFindingCount int `json:"open_finding_count"`
	CriticalCount    int `json:"critical_count"`
	WarningCount     int `json:"warning_count"`
	InfoCount        int `json:"info_count"`
}

type Coverage struct {
	ServiceCount                int    `json:"service_count"`
	Percent                     int    `json:"percent"`
	MissingSignals              int    `json:"missing_signals"`
	UnknownSignals              int    `json:"unknown_signals"`
	EvaluableSignals            int    `json:"evaluable_signals"`
	EvidenceState               string `json:"evidence_state"`
	EvidenceCompletenessPercent int    `json:"evidence_completeness_percent"`
}

type Cost struct {
	OpportunityCount         int      `json:"opportunity_count"`
	QuantifiedCount          int      `json:"quantified_count"`
	CurrentSeries            int64    `json:"current_series"`
	PotentialSeriesReduction int64    `json:"potential_series_reduction"`
	PotentialMonthlySavings  *float64 `json:"potential_monthly_savings,omitempty"`
	Currency                 string   `json:"currency,omitempty"`
}

type ConnectorEvidence struct {
	InstanceRef       string `json:"instance_ref"`
	Type              string `json:"type"`
	Group             string `json:"group"`
	Status            string `json:"status"`
	ResourceCount     int    `json:"resource_count"`
	RelationshipCount int    `json:"relationship_count"`
	SucceededChecks   int    `json:"succeeded_checks"`
	WarningChecks     int    `json:"warning_checks"`
	FailedChecks      int    `json:"failed_checks"`
}

type FindingEvidence struct {
	Ref          string `json:"ref"`
	Type         string `json:"type"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	RiskScore    *int   `json:"risk_score,omitempty"`
	ResourceType string `json:"resource_type"`
	ResourceRef  string `json:"resource_ref"`
}

func AnonymousID(kind string, parts ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(strings.TrimSpace(kind)))
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
	}
	return strings.TrimSpace(kind) + "_" + hex.EncodeToString(hash.Sum(nil))[:24]
}

func (b *Bundle) Normalize() {
	if b.ContractVersion == "" {
		b.ContractVersion = ContractVersion
	}
	if b.Product.Name == "" {
		b.Product.Name = "MoniCheck"
	}
	if b.Product.Mode == "" {
		b.Product.Mode = "LOCAL"
	}
	if b.Connectors == nil {
		b.Connectors = []ConnectorEvidence{}
	}
	if b.Findings == nil {
		b.Findings = []FindingEvidence{}
	}
	sort.Slice(b.Connectors, func(i, j int) bool { return b.Connectors[i].InstanceRef < b.Connectors[j].InstanceRef })
	sort.Slice(b.Findings, func(i, j int) bool { return b.Findings[i].Ref < b.Findings[j].Ref })
}

func (b Bundle) Validate() error {
	if b.ContractVersion != ContractVersion {
		return fmt.Errorf("contract_version must be %s", ContractVersion)
	}
	if strings.TrimSpace(b.BundleID) == "" || strings.TrimSpace(b.Execution.Ref) == "" {
		return errors.New("bundle and execution references are required")
	}
	if b.GeneratedAt.IsZero() || b.Execution.StartedAt.IsZero() || b.Execution.FinishedAt.IsZero() {
		return errors.New("bundle timestamps are required")
	}
	if b.Product.Name != "MoniCheck" || b.Product.Mode != "LOCAL" {
		return errors.New("product boundary must be MoniCheck LOCAL")
	}
	if b.Summary.ResourceCount < 0 || b.Summary.FindingCount < 0 || b.Coverage.Percent < 0 || b.Coverage.Percent > 100 {
		return errors.New("bundle counts or coverage are invalid")
	}
	for _, item := range b.Connectors {
		if item.InstanceRef == "" || item.Type == "" || item.Group == "" || item.Status == "" {
			return errors.New("connector evidence is incomplete")
		}
	}
	for _, item := range b.Findings {
		if item.Ref == "" || item.Type == "" || item.ResourceRef == "" || item.ResourceType == "" {
			return errors.New("finding evidence is incomplete")
		}
	}
	return nil
}
