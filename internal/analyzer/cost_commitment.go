package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

const OverdueCostCommitmentAnalyzerID = "builtin.overdue_cost_commitment"

type OverdueCostCommitmentAnalyzer struct{}

func NewOverdueCostCommitmentAnalyzer() *OverdueCostCommitmentAnalyzer {
	return &OverdueCostCommitmentAnalyzer{}
}

func (a *OverdueCostCommitmentAnalyzer) ID() string {
	return OverdueCostCommitmentAnalyzerID
}

func (a *OverdueCostCommitmentAnalyzer) Name() string {
	return "Overdue Cost Commitment"
}

func (a *OverdueCostCommitmentAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OverdueCostCommitmentAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *OverdueCostCommitmentAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Resources == nil || analysis.Findings == nil || analysis.FindingWorkflow == nil {
		return []model.Finding{}, nil
	}
	summary, err := report.BuildCostOutcomeSummary(ctx, &storage.Store{
		Resources: analysis.Resources, Findings: analysis.Findings, FindingWorkflow: analysis.FindingWorkflow,
	}, storage.ResourceFilter{}, report.CostPricing{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0, summary.OverdueCommitmentCount)
	for _, item := range summary.Items {
		if !item.Overdue || item.DueAt == nil || item.CommitmentID == "" || item.State == report.CostOutcomeStateRealized {
			continue
		}
		age := now.Sub(*item.DueAt)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), item.CommitmentID),
			Type:     "OverdueCostCommitment",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryCost,
			Resource: item.Resource,
			Evidence: []string{fmt.Sprintf(
				"cost commitment %q owned by %q is %s overdue; current outcome state is %s",
				item.CommitmentID, item.Owner, formatVerificationAge(age), item.State,
			)},
			Recommendation: "Review the accountable owner and measurement evidence, then verify and accept the realized outcome or cancel the commitment with a reason.",
			Metadata: map[string]string{
				"analyzer_id":               a.ID(),
				"source_finding_id":         item.FindingID,
				"commitment_id":             item.CommitmentID,
				"owner":                     item.Owner,
				"due_at":                    item.DueAt.Format(time.RFC3339Nano),
				"overdue_seconds":           strconv.FormatInt(int64(age.Seconds()), 10),
				"outcome_state":             item.State,
				"approved_series_reduction": strconv.FormatInt(item.ApprovedSeriesReduction, 10),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}
