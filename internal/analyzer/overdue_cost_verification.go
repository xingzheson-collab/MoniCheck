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

const OverdueCostVerificationAnalyzerID = "builtin.overdue_cost_verification"

type OverdueCostVerificationAnalyzer struct{}

func NewOverdueCostVerificationAnalyzer() *OverdueCostVerificationAnalyzer {
	return &OverdueCostVerificationAnalyzer{}
}

func (a *OverdueCostVerificationAnalyzer) ID() string {
	return OverdueCostVerificationAnalyzerID
}

func (a *OverdueCostVerificationAnalyzer) Name() string {
	return "Overdue Cost Verification"
}

func (a *OverdueCostVerificationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OverdueCostVerificationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *OverdueCostVerificationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Resources == nil || analysis.Findings == nil || analysis.FindingWorkflow == nil {
		return []model.Finding{}, nil
	}
	sla := durationConfig(analysis.Config, "cost_verification_sla", report.DefaultCostVerificationSLA)
	summary, err := report.BuildCostVerificationSummary(ctx, &storage.Store{
		Resources:       analysis.Resources,
		Findings:        analysis.Findings,
		FindingWorkflow: analysis.FindingWorkflow,
	}, storage.ResourceFilter{}, report.CostPricing{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, item := range summary.Items {
		age := now.Sub(item.BaselineCapturedAt)
		if age <= sla || !report.CostVerificationNeedsAttention(item.State) {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), item.FindingID),
			Type:     "OverdueCostVerification",
			Severity: model.SeverityWarning,
			Resource: item.Resource,
			Evidence: []string{fmt.Sprintf(
				"cost baseline for %q has remained %s for %s since %s, exceeding the %s verification SLA",
				item.Resource.Name,
				item.State,
				formatVerificationAge(age),
				item.BaselineCapturedAt.Format(time.RFC3339),
				sla,
			)},
			Recommendation: "运行负责该 Metric 的 Connector，并恢复同一来源的可比 series 测量；确认优化结果后重新执行 Cost Verification。",
			Metadata: map[string]string{
				"analyzer_id":              a.ID(),
				"source_finding_id":        item.FindingID,
				"baseline_at":              item.BaselineCapturedAt.Format(time.RFC3339Nano),
				"verification_state":       item.State,
				"baseline_age_seconds":     strconv.FormatInt(int64(age.Seconds()), 10),
				"verification_sla_seconds": strconv.FormatInt(int64(sla.Seconds()), 10),
				"connector_id":             item.ConnectorID,
				"measurement_source":       item.MeasurementSource,
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

func formatVerificationAge(age time.Duration) string {
	if age < 0 {
		return "0s"
	}
	return age.Round(time.Minute).String()
}
