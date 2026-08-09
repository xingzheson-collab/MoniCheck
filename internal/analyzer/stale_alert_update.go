package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const StaleAlertUpdateAnalyzerID = "builtin.stale_alert_update"

const defaultStaleAlertUpdateThreshold = time.Hour

type StaleAlertUpdateAnalyzer struct{}

func NewStaleAlertUpdateAnalyzer() *StaleAlertUpdateAnalyzer {
	return &StaleAlertUpdateAnalyzer{}
}

func (a *StaleAlertUpdateAnalyzer) ID() string {
	return StaleAlertUpdateAnalyzerID
}

func (a *StaleAlertUpdateAnalyzer) Name() string {
	return "Stale Alert Update"
}

func (a *StaleAlertUpdateAnalyzer) Version() string {
	return "0.1.0"
}

func (a *StaleAlertUpdateAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert}
}

func (a *StaleAlertUpdateAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alerts, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	threshold := durationConfig(analysis.Config, "stale_alert_update_threshold", defaultStaleAlertUpdateThreshold)
	findings := make([]model.Finding, 0)
	for _, alert := range alerts {
		if !supportsAlertRefreshAnalysis(alert.Source.System) || alert.Status != model.ResourceStatusActive || !isActiveAlertState(alert.Metadata[model.MetadataAlertState]) {
			continue
		}
		updatedAt, ok := parseAlertUpdatedAt(alert)
		if !ok {
			continue
		}
		age := now.Sub(updatedAt)
		if age <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "StaleAlertUpdate",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s alert %q was last updated at %s, threshold is %s", alert.Source.System, alert.Name, updatedAt.Format(time.RFC3339), threshold),
			},
			Recommendation: "检查规则评估状态、告警刷新链路和告警平台集群状态；活跃告警长时间不刷新可能表示上游评估、推送或事件同步异常。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"updated_at":  updatedAt.Format(time.RFC3339),
				"age":         age.String(),
				"threshold":   threshold.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func supportsAlertRefreshAnalysis(system string) bool {
	return system == "alertmanager" || system == "n9e"
}

func parseAlertUpdatedAt(alert model.Resource) (time.Time, bool) {
	raw := alert.Metadata[model.MetadataUpdatedAt]
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
