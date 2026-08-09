package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	N9ECurrentAlertDiscoveryUnavailableAnalyzerID = "builtin.n9e_current_alert_discovery_unavailable"
	N9EHistoryDiscoveryUnavailableAnalyzerID      = "builtin.n9e_history_discovery_unavailable"
	N9EEventDiscoveryTruncatedAnalyzerID          = "builtin.n9e_event_discovery_truncated"
)

type N9ERuntimeCoverageAnalyzer struct {
	id   string
	name string
}

func NewN9ECurrentAlertDiscoveryUnavailableAnalyzer() *N9ERuntimeCoverageAnalyzer {
	return &N9ERuntimeCoverageAnalyzer{id: N9ECurrentAlertDiscoveryUnavailableAnalyzerID, name: "N9E Current Alert Discovery Unavailable"}
}

func NewN9EHistoryDiscoveryUnavailableAnalyzer() *N9ERuntimeCoverageAnalyzer {
	return &N9ERuntimeCoverageAnalyzer{id: N9EHistoryDiscoveryUnavailableAnalyzerID, name: "N9E History Discovery Unavailable"}
}

func NewN9EEventDiscoveryTruncatedAnalyzer() *N9ERuntimeCoverageAnalyzer {
	return &N9ERuntimeCoverageAnalyzer{id: N9EEventDiscoveryTruncatedAnalyzerID, name: "N9E Event Discovery Truncated"}
}

func (a *N9ERuntimeCoverageAnalyzer) ID() string      { return a.id }
func (a *N9ERuntimeCoverageAnalyzer) Name() string    { return a.name }
func (a *N9ERuntimeCoverageAnalyzer) Version() string { return "0.1.0" }
func (a *N9ERuntimeCoverageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *N9ERuntimeCoverageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive ||
			resource.Source.System != "n9e" ||
			resource.Metadata[model.MetadataN9ERuntime] != "true" {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *N9ERuntimeCoverageAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}
	switch a.id {
	case N9ECurrentAlertDiscoveryUnavailableAnalyzerID:
		if resource.Metadata[model.MetadataN9ECurrentAlertDiscoveryAvailable] != "false" {
			return model.Finding{}, false
		}
		findingType = "N9ECurrentAlertDiscoveryUnavailable"
		evidence = "N9E current alert discovery endpoint is unavailable"
		recommendation = "检查 MoniCheck 到 N9E 当前告警接口的网络、认证和 API 兼容性；恢复后重新同步，确认活动告警治理覆盖完整。"
	case N9EHistoryDiscoveryUnavailableAnalyzerID:
		if resource.Metadata[model.MetadataN9EHistoryDiscoveryAvailable] != "false" {
			return model.Finding{}, false
		}
		findingType = "N9EHistoryDiscoveryUnavailable"
		evidence = "N9E alert history discovery endpoint is unavailable"
		recommendation = "检查 MoniCheck 到 N9E 历史告警接口的网络、认证和 API 兼容性；恢复后重新同步，确认噪声、抖动和恢复质量分析重新获得历史样本。"
	case N9EEventDiscoveryTruncatedAnalyzerID:
		parts := make([]string, 0, 2)
		if resource.Metadata[model.MetadataN9ECurrentAlertEventsTruncated] == "true" {
			parts = append(parts, eventCoverageEvidence("current", resource.Metadata[model.MetadataN9ECurrentAlertEventCount], resource.Metadata[model.MetadataN9ECurrentAlertEventTotal]))
			metadata["current_alert_events_truncated"] = "true"
		}
		if resource.Metadata[model.MetadataN9EHistoryEventsTruncated] == "true" {
			parts = append(parts, eventCoverageEvidence("history", resource.Metadata[model.MetadataN9EHistoryEventCount], resource.Metadata[model.MetadataN9EHistoryEventTotal]))
			metadata["history_events_truncated"] = "true"
		}
		if len(parts) == 0 {
			return model.Finding{}, false
		}
		findingType = "N9EEventDiscoveryTruncated"
		evidence = strings.Join(parts, "; ")
		recommendation = "缩小 N9E 历史窗口或提高经过容量评估的事件上限，并检查持续高告警量；重新同步后确认当前与历史事件发现不再截断。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategoryReliability,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func eventCoverageEvidence(kind string, retained string, total string) string {
	if total != "" && total != "0" {
		return fmt.Sprintf("N9E %s alert discovery retained %s of %s events", kind, retained, total)
	}
	return fmt.Sprintf("N9E %s alert discovery reached its configured limit after retaining %s events", kind, retained)
}
