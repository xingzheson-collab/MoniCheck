package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MissingRunbookAnalyzerID = "builtin.missing_runbook"

type MissingRunbookAnalyzer struct{}

func NewMissingRunbookAnalyzer() *MissingRunbookAnalyzer {
	return &MissingRunbookAnalyzer{}
}

func (a *MissingRunbookAnalyzer) ID() string {
	return MissingRunbookAnalyzerID
}

func (a *MissingRunbookAnalyzer) Name() string {
	return "Missing Runbook"
}

func (a *MissingRunbookAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MissingRunbookAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeAlert}
}

func (a *MissingRunbookAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listRunbookResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Type == model.ResourceTypeAlertRule && (resource.Status != model.ResourceStatusActive || isDisabledAlert(resource)) {
			continue
		}
		if resource.Type == model.ResourceTypeAlert && !isActiveRuntimeAlert(resource) {
			continue
		}
		severity, ok := severityValue(resource)
		if !ok || strings.EqualFold(strings.TrimSpace(severity), "info") {
			continue
		}
		if hasRunbook(resource.Metadata) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "MissingRunbook",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q with severity %q has no runbook metadata or annotation", runbookResourceKind(resource), resource.Name, severity),
			},
			Recommendation: "为 critical 或 warning 告警/告警规则补充 runbook 链接，写清排查入口、止血步骤和升级路径，降低值班处理成本。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"severity":    severity,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func listRunbookResources(ctx context.Context, resources storage.ResourceRepository) ([]model.Resource, error) {
	alertRules, err := resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	alerts, err := resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}
	return append(alertRules, alerts...), nil
}

func runbookResourceKind(resource model.Resource) string {
	if resource.Type == model.ResourceTypeAlert {
		return "alert"
	}
	return "alert rule"
}

func hasRunbook(metadata map[string]string) bool {
	if metadata[model.MetadataDatadogRunbookConfigured] == "true" ||
		metadata[model.MetadataNewRelicRunbookConfigured] == "true" {
		return true
	}
	for _, key := range runbookMetadataKeys() {
		if strings.TrimSpace(metadata[key]) != "" {
			return true
		}
	}
	return false
}

func runbookMetadataKeys() []string {
	return []string{
		"runbook",
		"runbook_url",
		"runbookUrl",
		"runbookURL",
		"annotation.runbook",
		"annotation.runbook_url",
		"annotation.runbookUrl",
		"annotation.runbookURL",
	}
}
