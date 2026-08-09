package localruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"monicheck/internal/model"
	"monicheck/internal/storage"
	"monicheck/pkg/evidence"
)

type governanceEvidenceSummary struct {
	ResourceCount                       int           `json:"resource_count"`
	FindingCount                        int           `json:"finding_count"`
	OpenFindingCount                    int           `json:"open_finding_count"`
	CriticalCount                       int           `json:"critical_count"`
	WarningCount                        int           `json:"warning_count"`
	InfoCount                           int           `json:"info_count"`
	CoverageServiceCount                int           `json:"coverage_service_count"`
	CoveragePercent                     int           `json:"coverage_percent"`
	CoverageMissingSignals              int           `json:"coverage_missing_signals"`
	CoverageUnknownSignals              int           `json:"coverage_unknown_signals"`
	CoverageEvaluableSignals            int           `json:"coverage_evaluable_signals"`
	CoverageEvidenceState               string        `json:"coverage_evidence_state"`
	CoverageEvidenceCompletenessPercent int           `json:"coverage_evidence_completeness_percent"`
	Cost                                evidence.Cost `json:"cost_opportunities"`
}

func (r *Runtime) EvidenceBundle(ctx context.Context) (evidence.Bundle, error) {
	export, err := r.LatestReport(ctx)
	if err != nil {
		return evidence.Bundle{}, err
	}
	var summary governanceEvidenceSummary
	if err := json.Unmarshal([]byte(export.Content), &summary); err != nil {
		return evidence.Bundle{}, fmt.Errorf("decode local governance summary: %w", err)
	}
	findings, err := r.Store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return evidence.Bundle{}, err
	}
	bundle := evidence.Bundle{
		ContractVersion: evidence.ContractVersion,
		BundleID:        evidence.AnonymousID("bundle", r.Execution.ID, export.ID),
		GeneratedAt:     export.CreatedAt,
		Product:         evidence.Product{Name: "MoniCheck", Mode: "LOCAL"},
		Execution:       evidence.Execution{Ref: evidence.AnonymousID("execution", r.Execution.ID), Status: string(r.Execution.Status), StartedAt: r.Execution.StartedAt, FinishedAt: r.Execution.FinishedAt, AnalyzerCount: len(r.Execution.AnalyzerIDs)},
		Summary:         evidence.Summary{ResourceCount: summary.ResourceCount, FindingCount: summary.FindingCount, OpenFindingCount: summary.OpenFindingCount, CriticalCount: summary.CriticalCount, WarningCount: summary.WarningCount, InfoCount: summary.InfoCount},
		Coverage:        evidence.Coverage{ServiceCount: summary.CoverageServiceCount, Percent: summary.CoveragePercent, MissingSignals: summary.CoverageMissingSignals, UnknownSignals: summary.CoverageUnknownSignals, EvaluableSignals: summary.CoverageEvaluableSignals, EvidenceState: summary.CoverageEvidenceState, EvidenceCompletenessPercent: summary.CoverageEvidenceCompletenessPercent},
		Cost:            summary.Cost,
		Connectors:      connectorEvidence(r.Engine.ConnectorStatuses()),
		Findings:        findingEvidence(findings),
	}
	bundle.Normalize()
	if err := bundle.Validate(); err != nil {
		return evidence.Bundle{}, fmt.Errorf("validate evidence bundle: %w", err)
	}
	return bundle, nil
}

func connectorEvidence(statuses []model.ConnectorStatus) []evidence.ConnectorEvidence {
	result := make([]evidence.ConnectorEvidence, 0, len(statuses))
	for _, status := range statuses {
		item := evidence.ConnectorEvidence{InstanceRef: evidence.AnonymousID("connector", status.ID), Type: strings.SplitN(status.ID, ":", 2)[0], Group: ConnectorGroup(status.ID), Status: string(status.Status), ResourceCount: status.ResourceCount, RelationshipCount: status.RelationshipCount}
		for _, diagnostic := range status.Diagnostics {
			switch diagnostic.Status {
			case model.ExecutionStatusSucceeded:
				item.SucceededChecks++
			case model.ExecutionStatusWarning:
				item.WarningChecks++
			case model.ExecutionStatusFailed:
				item.FailedChecks++
			}
		}
		result = append(result, item)
	}
	return result
}

func findingEvidence(findings []model.Finding) []evidence.FindingEvidence {
	result := make([]evidence.FindingEvidence, 0, len(findings))
	for _, finding := range findings {
		item := evidence.FindingEvidence{Ref: evidence.AnonymousID("finding", finding.ID), Type: finding.Type, Category: string(finding.Category), Severity: string(finding.Severity), Status: string(finding.Status), ResourceType: string(finding.Resource.Type), ResourceRef: evidence.AnonymousID("resource", finding.Resource.ID)}
		if finding.RiskScore != nil {
			score := finding.RiskScore.Score
			item.RiskScore = &score
		}
		result = append(result, item)
	}
	return result
}
