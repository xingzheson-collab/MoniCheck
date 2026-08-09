package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const LongFiringAlertAnalyzerID = "builtin.long_firing_alert"

const defaultLongFiringAlertThreshold = 24 * time.Hour

type LongFiringAlertAnalyzer struct{}

func NewLongFiringAlertAnalyzer() *LongFiringAlertAnalyzer {
	return &LongFiringAlertAnalyzer{}
}

func (a *LongFiringAlertAnalyzer) ID() string {
	return LongFiringAlertAnalyzerID
}

func (a *LongFiringAlertAnalyzer) Name() string {
	return "Long Firing Alert"
}

func (a *LongFiringAlertAnalyzer) Version() string {
	return "0.1.0"
}

func (a *LongFiringAlertAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert}
}

func (a *LongFiringAlertAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alerts, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	threshold := durationConfig(analysis.Config, "long_firing_alert_threshold", defaultLongFiringAlertThreshold)
	for _, alert := range alerts {
		if alert.Metadata[model.MetadataAlertState] != "" && alert.Metadata[model.MetadataAlertState] != "active" {
			continue
		}
		startsAt, ok := parseAlertStartsAt(alert)
		if !ok {
			continue
		}
		duration := now.Sub(startsAt)
		if duration <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "LongFiringAlert",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert %q has been firing since %s, threshold is %s", alert.Name, startsAt.Format(time.RFC3339), threshold),
			},
			Recommendation: "检查该告警是否长期无人处理、阈值过严或缺少自动恢复条件；长期 firing 的告警会降低告警信任度。",
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

func parseAlertStartsAt(alert model.Resource) (time.Time, bool) {
	raw := alert.Metadata[model.MetadataStartsAt]
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
