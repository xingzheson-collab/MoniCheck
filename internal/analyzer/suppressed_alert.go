package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const SuppressedAlertAnalyzerID = "builtin.suppressed_alert"

type SuppressedAlertAnalyzer struct{}

func NewSuppressedAlertAnalyzer() *SuppressedAlertAnalyzer {
	return &SuppressedAlertAnalyzer{}
}

func (a *SuppressedAlertAnalyzer) ID() string {
	return SuppressedAlertAnalyzerID
}

func (a *SuppressedAlertAnalyzer) Name() string {
	return "Suppressed Alert"
}

func (a *SuppressedAlertAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SuppressedAlertAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert}
}

func (a *SuppressedAlertAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alerts, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alert := range alerts {
		if alert.Source.System != "alertmanager" {
			continue
		}
		if alert.Status != model.ResourceStatusActive {
			continue
		}
		if !isActiveAlertState(alert.Metadata[model.MetadataAlertState]) {
			continue
		}
		evidence := suppressedAlertEvidence(alert)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "SuppressedAlert",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence:       evidence,
			Recommendation: "确认该告警被静默或抑制是否符合预期；长期 suppressed 的告警建议修正规则、调整路由或补充静默原因。",
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

func suppressedAlertEvidence(alert model.Resource) []string {
	evidence := make([]string, 0, 2)
	if value := strings.TrimSpace(alert.Metadata[model.MetadataSilencedBy]); value != "" {
		evidence = append(evidence, fmt.Sprintf("alert is silenced by %s", value))
	}
	if value := strings.TrimSpace(alert.Metadata[model.MetadataInhibitedBy]); value != "" {
		evidence = append(evidence, fmt.Sprintf("alert is inhibited by %s", value))
	}
	return evidence
}
