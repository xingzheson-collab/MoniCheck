package analyzer

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"monicheck/internal/model"
)

const InvalidRunbookURLAnalyzerID = "builtin.invalid_runbook_url"

type InvalidRunbookURLAnalyzer struct{}

func NewInvalidRunbookURLAnalyzer() *InvalidRunbookURLAnalyzer {
	return &InvalidRunbookURLAnalyzer{}
}

func (a *InvalidRunbookURLAnalyzer) ID() string {
	return InvalidRunbookURLAnalyzerID
}

func (a *InvalidRunbookURLAnalyzer) Name() string {
	return "Invalid Runbook URL"
}

func (a *InvalidRunbookURLAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InvalidRunbookURLAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeAlert}
}

func (a *InvalidRunbookURLAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		runbookKey, runbookValue, ok := runbookValue(resource.Metadata)
		if !ok {
			continue
		}
		evidence := invalidRunbookURLEvidence(runbookValue)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "InvalidRunbookURL",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: append([]string{
				fmt.Sprintf("%s %q has invalid runbook value in %s", runbookResourceKind(resource), resource.Name, runbookKey),
			}, evidence...),
			Recommendation: "将 runbook 更新为可点击的 http/https URL，确保值班人员可以从告警通知直接进入排查和止血文档。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"runbook_key": runbookKey,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func runbookValue(metadata map[string]string) (string, string, bool) {
	for _, key := range runbookMetadataKeys() {
		value := strings.TrimSpace(metadata[key])
		if value != "" {
			return key, value, true
		}
	}
	return "", "", false
}

func invalidRunbookURLEvidence(raw string) []string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return []string{fmt.Sprintf("runbook URL %q is not an absolute URL", raw)}
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return []string{fmt.Sprintf("runbook URL %q uses unsupported scheme %q", raw, parsed.Scheme)}
	}
	return nil
}
