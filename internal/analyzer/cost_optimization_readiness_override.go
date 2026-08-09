package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/report"
	"monicheck/internal/storage"
)

const CostOptimizationReadinessOverrideAnalyzerID = "builtin.cost_optimization_readiness_override"

type CostOptimizationReadinessOverrideAnalyzer struct{}

func NewCostOptimizationReadinessOverrideAnalyzer() *CostOptimizationReadinessOverrideAnalyzer {
	return &CostOptimizationReadinessOverrideAnalyzer{}
}

func (a *CostOptimizationReadinessOverrideAnalyzer) ID() string {
	return CostOptimizationReadinessOverrideAnalyzerID
}

func (a *CostOptimizationReadinessOverrideAnalyzer) Name() string {
	return "Cost Optimization Readiness Override"
}

func (a *CostOptimizationReadinessOverrideAnalyzer) Version() string {
	return "0.1.0"
}

func (a *CostOptimizationReadinessOverrideAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *CostOptimizationReadinessOverrideAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Resources == nil || analysis.Findings == nil || analysis.FindingWorkflow == nil {
		return []model.Finding{}, nil
	}
	store := &storage.Store{
		Resources:       analysis.Resources,
		Findings:        analysis.Findings,
		FindingWorkflow: analysis.FindingWorkflow,
	}
	verification, err := report.BuildCostVerificationSummary(ctx, store, storage.ResourceFilter{}, report.CostPricing{})
	if err != nil {
		return nil, err
	}
	events, err := analysis.FindingWorkflow.List(ctx, "")
	if err != nil {
		return nil, err
	}
	latest := make(map[string]model.FindingWorkflowEvent)
	for _, event := range events {
		if event.Action != report.CostBaselineCapturedAction {
			continue
		}
		current, found := latest[event.FindingID]
		if !found || event.CreatedAt.After(current.CreatedAt) {
			latest[event.FindingID] = event
		}
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, item := range verification.Items {
		event, found := latest[item.FindingID]
		if !found || !strings.EqualFold(strings.TrimSpace(event.Metadata["readiness_override"]), "true") ||
			!report.CostVerificationNeedsAttention(item.State) {
			continue
		}
		reasons := safeReadinessBlockingReasons(event.Metadata["readiness_blocking_reasons"])
		reasonText := "unknown readiness evidence"
		if len(reasons) > 0 {
			reasonText = strings.Join(reasons, ", ")
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), item.FindingID),
			Type:     "CostOptimizationReadinessOverride",
			Severity: model.SeverityWarning,
			Resource: item.Resource,
			Evidence: []string{fmt.Sprintf(
				"cost baseline for %q was captured with a readiness override while blocked by %s and remains %s",
				item.Resource.Name,
				reasonText,
				item.State,
			)},
			Recommendation: "补齐 Metric inventory、Dashboard/Rule 使用证据和观察窗口，人工复核所有依赖；在可信验证完成前不要执行不可逆的采集删除。",
			Metadata: map[string]string{
				"analyzer_id":                a.ID(),
				"source_finding_id":          item.FindingID,
				"baseline_at":                event.CreatedAt.Format(time.RFC3339Nano),
				"readiness_state_at_capture": safeReadinessState(event.Metadata["readiness_state"]),
				"readiness_blocking_reasons": strings.Join(reasons, ","),
				"verification_state":         item.State,
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

func safeReadinessState(value string) string {
	switch strings.TrimSpace(value) {
	case report.CostReadinessReady,
		report.CostReadinessIncompleteInventory,
		report.CostReadinessIncompleteCoverage,
		report.CostReadinessNeedsObservation:
		return strings.TrimSpace(value)
	default:
		return "UNKNOWN"
	}
}

func safeReadinessBlockingReasons(value string) []string {
	allowed := map[string]bool{
		"metric_inventory_incomplete":    true,
		"dashboard_evidence_unavailable": true,
		"rule_evidence_unavailable":      true,
		"observation_window_incomplete":  true,
	}
	seen := map[string]bool{}
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if !allowed[item] || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}
