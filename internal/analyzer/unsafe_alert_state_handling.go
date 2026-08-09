package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnsafeAlertStateHandlingAnalyzerID = "builtin.unsafe_alert_state_handling"

type UnsafeAlertStateHandlingAnalyzer struct{}

func NewUnsafeAlertStateHandlingAnalyzer() *UnsafeAlertStateHandlingAnalyzer {
	return &UnsafeAlertStateHandlingAnalyzer{}
}

func (a *UnsafeAlertStateHandlingAnalyzer) ID() string {
	return UnsafeAlertStateHandlingAnalyzerID
}

func (a *UnsafeAlertStateHandlingAnalyzer) Name() string {
	return "Unsafe Alert State Handling"
}

func (a *UnsafeAlertStateHandlingAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnsafeAlertStateHandlingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *UnsafeAlertStateHandlingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alertRule := range alertRules {
		if alertRule.Status != model.ResourceStatusActive || isDisabledAlert(alertRule) {
			continue
		}
		evidence := unsafeAlertStateEvidence(alertRule)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "UnsafeAlertStateHandling",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence:       evidence,
			Recommendation: "将 Grafana 告警的 NoData/执行错误处理调整为 Alerting、NoData 或 Error 等显式状态，避免查询失败或数据缺失时被误判为正常。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func unsafeAlertStateEvidence(alertRule model.Resource) []string {
	evidence := make([]string, 0, 2)
	if state := strings.TrimSpace(alertRule.Metadata[model.MetadataNoDataState]); isUnsafeGrafanaState(state) {
		evidence = append(evidence, fmt.Sprintf("no data state is %q", state))
	}
	if state := strings.TrimSpace(alertRule.Metadata[model.MetadataExecErrState]); isUnsafeGrafanaState(state) {
		evidence = append(evidence, fmt.Sprintf("execution error state is %q", state))
	}
	return evidence
}

func isUnsafeGrafanaState(state string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(state), "_", ""))
	return normalized == "ok" || normalized == "keeplaststate"
}
