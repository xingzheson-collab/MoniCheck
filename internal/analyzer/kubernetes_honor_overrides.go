package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesMonitorHonorLabelsNotOverriddenAnalyzerID     = "builtin.kubernetes_monitor_honor_labels_not_overridden"
	KubernetesMonitorHonorTimestampsNotOverriddenAnalyzerID = "builtin.kubernetes_monitor_honor_timestamps_not_overridden"
)

type KubernetesMonitorHonorLabelsNotOverriddenAnalyzer struct{}
type KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer struct{}

func NewKubernetesMonitorHonorLabelsNotOverriddenAnalyzer() *KubernetesMonitorHonorLabelsNotOverriddenAnalyzer {
	return &KubernetesMonitorHonorLabelsNotOverriddenAnalyzer{}
}

func NewKubernetesMonitorHonorTimestampsNotOverriddenAnalyzer() *KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer {
	return &KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer{}
}

func (a *KubernetesMonitorHonorLabelsNotOverriddenAnalyzer) ID() string {
	return KubernetesMonitorHonorLabelsNotOverriddenAnalyzerID
}
func (a *KubernetesMonitorHonorLabelsNotOverriddenAnalyzer) Name() string {
	return "Kubernetes Monitor Honor Labels Not Overridden"
}
func (a *KubernetesMonitorHonorLabelsNotOverriddenAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorHonorLabelsNotOverriddenAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorHonorLabelsNotOverriddenAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesHonorOverrideFindings(ctx, analysis, a.ID())
}

func (a *KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer) ID() string {
	return KubernetesMonitorHonorTimestampsNotOverriddenAnalyzerID
}
func (a *KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer) Name() string {
	return "Kubernetes Monitor Honor Timestamps Not Overridden"
}
func (a *KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}
func (a *KubernetesMonitorHonorTimestampsNotOverriddenAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesHonorOverrideFindings(ctx, analysis, a.ID())
}

func kubernetesHonorOverrideFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		finding, matched := kubernetesHonorOverrideFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesHonorOverrideFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Type != model.ResourceTypeTarget || honorOverrideMetadataInt(resource, "prometheus_selected_count") == 0 {
		return model.Finding{}, false
	}
	settingCount := 0
	unprotectedCount := 0
	findingType := ""
	category := model.FindingCategoryQuality
	evidenceSubject := ""
	recommendation := ""
	switch analyzerID {
	case KubernetesMonitorHonorLabelsNotOverriddenAnalyzerID:
		if kind != "ServiceMonitor" && kind != "PodMonitor" && kind != "ScrapeConfig" {
			return model.Finding{}, false
		}
		settingCount = honorOverrideMetadataInt(resource, "monitor_honor_labels_count")
		unprotectedCount = honorOverrideMetadataInt(resource, "prometheus_honor_labels_unprotected_count")
		findingType = "KubernetesMonitorHonorLabelsNotOverridden"
		evidenceSubject = "honorLabels endpoint/config setting"
		recommendation = "在所有选中该 Monitor 的 Prometheus/Agent 设置 overrideHonorLabels=true，或关闭 honorLabels，避免目标标签覆盖 Prometheus 生成的 job、instance 和发现标签。"
	case KubernetesMonitorHonorTimestampsNotOverriddenAnalyzerID:
		if kind != "ServiceMonitor" && kind != "PodMonitor" {
			return model.Finding{}, false
		}
		settingCount = honorOverrideMetadataInt(resource, "monitor_explicit_honor_timestamps_count")
		unprotectedCount = honorOverrideMetadataInt(resource, "prometheus_honor_timestamps_unprotected_count")
		findingType = "KubernetesMonitorHonorTimestampsNotOverridden"
		category = model.FindingCategoryReliability
		evidenceSubject = "explicit honorTimestamps setting"
		recommendation = "在所有选中该 Monitor 的 Prometheus/Agent 设置 overrideHonorTimestamps=true，或显式关闭 honorTimestamps，避免目标提供的过期或未来时间戳影响时序可靠性。"
	default:
		return model.Finding{}, false
	}
	if settingCount == 0 || unprotectedCount == 0 {
		return model.Finding{}, false
	}
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": resource.Metadata["namespace"], "explicit_setting_count": strconv.Itoa(settingCount), "unprotected_workload_count": strconv.Itoa(unprotectedCount)}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: model.SeverityWarning, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{fmt.Sprintf("Kubernetes %s %q has %d %s(s) not overridden by %d selecting workload(s)", kind, resource.Name, settingCount, evidenceSubject, unprotectedCount)}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func honorOverrideMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil {
		return 0
	}
	return value
}
