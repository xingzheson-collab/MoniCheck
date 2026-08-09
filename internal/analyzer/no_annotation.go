package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const NoAnnotationAnalyzerID = "builtin.no_annotation"

type NoAnnotationAnalyzer struct{}

func NewNoAnnotationAnalyzer() *NoAnnotationAnalyzer {
	return &NoAnnotationAnalyzer{}
}

func (a *NoAnnotationAnalyzer) ID() string {
	return NoAnnotationAnalyzerID
}

func (a *NoAnnotationAnalyzer) Name() string {
	return "No Annotation"
}

func (a *NoAnnotationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *NoAnnotationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *NoAnnotationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if hasAlertAnnotation(alertRule.Metadata) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "NoAnnotation",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q has no summary or description annotation", alertRule.Name),
			},
			Recommendation: "为告警规则补充 summary 或 description 注解，便于值班人员理解影响范围和处理方式。",
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

func hasAlertAnnotation(metadata map[string]string) bool {
	for _, key := range []string{"annotation.summary", "annotation.description", "annotation.message"} {
		if strings.TrimSpace(metadata[key]) != "" {
			return true
		}
	}
	return false
}
