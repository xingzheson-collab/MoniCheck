package localruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"monicheck/internal/buildinfo"
	"monicheck/internal/model"
	"monicheck/internal/report"
)

type ActivationReceipt struct {
	ContractVersion          string                    `json:"contract_version"`
	GeneratedAt              time.Time                 `json:"generated_at"`
	Outcome                  string                    `json:"outcome"`
	Ready                    bool                      `json:"ready"`
	TargetSeconds            int64                     `json:"target_seconds"`
	TimeToFirstReportSeconds *int64                    `json:"time_to_first_report_seconds,omitempty"`
	WithinTarget             *bool                     `json:"within_target,omitempty"`
	Build                    activationReceiptBuild    `json:"build"`
	Counts                   activationReceiptCounts   `json:"counts"`
	Coverage                 activationReceiptCoverage `json:"coverage"`
	Stages                   []activationReceiptStage  `json:"stages"`
	SharingMode              string                    `json:"sharing_mode"`
	ExcludedData             []string                  `json:"excluded_data"`
}

type activationReceiptBuild struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type activationReceiptCounts struct {
	Sources          int   `json:"sources"`
	Resources        int   `json:"resources"`
	Findings         int   `json:"findings"`
	Services         int   `json:"services"`
	InferredServices int   `json:"inferred_services"`
	CurrentSeries    int64 `json:"current_series"`
}

type activationReceiptCoverage struct {
	EvaluableSignals            int      `json:"evaluable_signals"`
	MissingSignals              int      `json:"missing_signals"`
	UnknownSignals              int      `json:"unknown_signals"`
	EvaluableCoveragePercent    *float64 `json:"evaluable_coverage_percent,omitempty"`
	EvidenceState               string   `json:"evidence_state"`
	EvidenceCompletenessPercent *float64 `json:"evidence_completeness_percent,omitempty"`
}

type activationReceiptStage struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Required bool   `json:"required"`
}

func (r *Runtime) ActivationReceipt(ctx context.Context) (ActivationReceipt, error) {
	export, err := r.LatestReport(ctx)
	if err != nil {
		return ActivationReceipt{}, err
	}
	var summary governanceEvidenceSummary
	if err := json.Unmarshal([]byte(export.Content), &summary); err != nil {
		return ActivationReceipt{}, fmt.Errorf("decode local governance summary: %w", err)
	}
	statuses := []model.ConnectorStatus{}
	if r.Engine != nil {
		statuses = r.Engine.ConnectorStatuses()
	}
	timing, found, err := report.LoadLocalActivationTiming(ctx, r.Store)
	if err != nil {
		return ActivationReceipt{}, err
	}
	return buildActivationReceipt(summary, statuses, timing, found, export.CreatedAt, buildinfo.Current()), nil
}

func buildActivationReceipt(summary governanceEvidenceSummary, statuses []model.ConnectorStatus, timing report.LocalActivationTiming, timingFound bool, generatedAt time.Time, build buildinfo.Info) ActivationReceipt {
	connectedSources := 0
	for _, status := range statuses {
		if status.Status == model.ExecutionStatusSucceeded || status.Status == model.ExecutionStatusWarning {
			connectedSources++
		}
	}
	ready := connectedSources > 0 && summary.ResourceCount > 0
	outcome := "BLOCKED"
	if ready {
		outcome = "READY"
	}
	coveragePercent := float64(summary.CoveragePercent)
	evidenceCompleteness := float64(summary.CoverageEvidenceCompletenessPercent)
	receipt := ActivationReceipt{
		ContractVersion: "activation-receipt.v1",
		GeneratedAt:     generatedAt.UTC(),
		Outcome:         outcome,
		Ready:           ready,
		TargetSeconds:   900,
		Build: activationReceiptBuild{
			Version: build.Version, Commit: build.Commit, OS: build.OS, Architecture: build.Architecture,
		},
		Counts: activationReceiptCounts{
			Sources: connectedSources, Resources: summary.ResourceCount, Findings: summary.FindingCount,
			Services: summary.CoverageServiceCount, InferredServices: summary.Coverage.InferredServiceCount,
			CurrentSeries: summary.Cost.CurrentSeries,
		},
		Coverage: activationReceiptCoverage{
			EvaluableSignals: summary.CoverageEvaluableSignals, MissingSignals: summary.CoverageMissingSignals,
			UnknownSignals: summary.CoverageUnknownSignals, EvaluableCoveragePercent: &coveragePercent,
			EvidenceState: summary.CoverageEvidenceState, EvidenceCompletenessPercent: &evidenceCompleteness,
		},
		Stages: []activationReceiptStage{
			{ID: "source", State: stageState(connectedSources > 0), Required: true},
			{ID: "inventory", State: stageState(summary.ResourceCount > 0), Required: true},
			{ID: "analysis", State: "COMPLETE", Required: true},
			{ID: "coverage", State: coverageStageState(summary), Required: false},
			{ID: "report", State: "COMPLETE", Required: true},
		},
		SharingMode: "MANUAL_ONLY",
		ExcludedData: []string{
			"credentials", "endpoints", "finding_evidence", "machine_identity", "resource_names", "user_identity",
		},
	}
	if timingFound && ready {
		seconds := timing.ElapsedMilliseconds / 1000
		within := timing.WithinTarget
		receipt.TargetSeconds = timing.TargetSeconds
		receipt.TimeToFirstReportSeconds = &seconds
		receipt.WithinTarget = &within
	}
	return receipt
}

func stageState(complete bool) string {
	if complete {
		return "COMPLETE"
	}
	return "BLOCKED"
}

func coverageStageState(summary governanceEvidenceSummary) string {
	if summary.CoverageServiceCount == 0 || summary.CoverageEvaluableSignals == 0 {
		return "UNEVALUATED"
	}
	if summary.CoverageUnknownSignals > 0 || summary.CoverageEvidenceCompletenessPercent < 100 {
		return "PARTIAL"
	}
	return "COMPLETE"
}
