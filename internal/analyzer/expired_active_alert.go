package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const ExpiredActiveAlertAnalyzerID = "builtin.expired_active_alert"

const defaultExpiredActiveAlertGrace = time.Minute

type ExpiredActiveAlertAnalyzer struct{}

func NewExpiredActiveAlertAnalyzer() *ExpiredActiveAlertAnalyzer {
	return &ExpiredActiveAlertAnalyzer{}
}

func (a *ExpiredActiveAlertAnalyzer) ID() string {
	return ExpiredActiveAlertAnalyzerID
}

func (a *ExpiredActiveAlertAnalyzer) Name() string {
	return "Expired Active Alert"
}

func (a *ExpiredActiveAlertAnalyzer) Version() string {
	return "0.1.0"
}

func (a *ExpiredActiveAlertAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert}
}

func (a *ExpiredActiveAlertAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alerts, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	grace := durationConfig(analysis.Config, "expired_active_alert_grace", defaultExpiredActiveAlertGrace)
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_expired_active_alerts", nil))
	findings := make([]model.Finding, 0)
	for _, alert := range alerts {
		if alert.Source.System != "alertmanager" || alert.Status != model.ResourceStatusActive || !isActiveAlertState(alert.Metadata[model.MetadataAlertState]) {
			continue
		}
		endsAt, ok := parseAlertEndsAt(alert)
		if !ok {
			continue
		}
		expiredFor := now.Sub(endsAt)
		if expiredFor <= grace {
			continue
		}
		if allowedResource(alert, allowed, model.MetadataFingerprint) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "ExpiredActiveAlert",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alertmanager alert %q is active but ended at %s, grace is %s", alert.Name, endsAt.Format(time.RFC3339), grace),
			},
			Recommendation: "检查 Alertmanager 告警刷新、resolve_timeout、Prometheus 推送链路和集群状态；active 告警 endsAt 已过期通常表示状态同步异常或告警数据滞留。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"ends_at":     endsAt.Format(time.RFC3339),
				"expired_for": expiredFor.Round(time.Second).String(),
				"grace":       grace.String(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func parseAlertEndsAt(alert model.Resource) (time.Time, bool) {
	raw := strings.TrimSpace(alert.Metadata[model.MetadataEndsAt])
	if raw == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
