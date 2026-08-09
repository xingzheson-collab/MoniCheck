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
	KubernetesMonitorAllRuntimeTargetsDroppedAnalyzerID   = "builtin.kubernetes_monitor_all_runtime_targets_dropped"
	KubernetesMonitorHighRuntimeTargetDropRatioAnalyzerID = "builtin.kubernetes_monitor_high_runtime_target_drop_ratio"
	defaultKubernetesRuntimeDropRatio                     = 0.5
	defaultKubernetesRuntimeDropMinimumObserved           = 5
)

type KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer struct{}

func NewKubernetesMonitorAllRuntimeTargetsDroppedAnalyzer() *KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer {
	return &KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer{}
}

func (a *KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer) ID() string {
	return KubernetesMonitorAllRuntimeTargetsDroppedAnalyzerID
}

func (a *KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer) Name() string {
	return "Kubernetes Monitor All Runtime Targets Dropped"
}

func (a *KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorAllRuntimeTargetsDroppedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		activeCount, droppedCount, observedCount, _, ok := kubernetesRuntimeDropCounts(target)
		if !ok || activeCount != 0 || droppedCount <= 0 {
			continue
		}
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorAllRuntimeTargetsDropped",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has %d observed runtime targets and all are dropped by target relabeling", kind, target.Name, namespace, observedCount),
			},
			Recommendation: "检查 targetRelabelings/relabel_configs 中的 keep/drop/keepequal/dropequal 条件和源标签，修复后确认至少一个目标进入 /api/v1/targets 的 activeTargets。",
			Metadata:       kubernetesRuntimeDropFindingMetadata(a.ID(), target, activeCount, droppedCount, observedCount),
			Status:         model.FindingStatusOpen,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	sortKubernetesRuntimeDropFindings(findings)
	return findings, nil
}

type KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer struct{}

func NewKubernetesMonitorHighRuntimeTargetDropRatioAnalyzer() *KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer {
	return &KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer{}
}

func (a *KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer) ID() string {
	return KubernetesMonitorHighRuntimeTargetDropRatioAnalyzerID
}

func (a *KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer) Name() string {
	return "Kubernetes Monitor High Runtime Target Drop Ratio"
}

func (a *KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesMonitorHighRuntimeTargetDropRatioAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		activeCount, droppedCount, observedCount, ratio, ok := kubernetesRuntimeDropCounts(target)
		if !ok || activeCount <= 0 || droppedCount <= 0 || observedCount < defaultKubernetesRuntimeDropMinimumObserved || ratio < defaultKubernetesRuntimeDropRatio {
			continue
		}
		kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
		namespace := kubernetesResourceNamespace(target)
		metadata := kubernetesRuntimeDropFindingMetadata(a.ID(), target, activeCount, droppedCount, observedCount)
		metadata["prometheus_runtime_dropped_target_ratio"] = fmt.Sprintf("%.4f", ratio)
		metadata["ratio_threshold"] = fmt.Sprintf("%.4f", defaultKubernetesRuntimeDropRatio)
		metadata["minimum_observed_targets"] = strconv.Itoa(defaultKubernetesRuntimeDropMinimumObserved)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesMonitorHighRuntimeTargetDropRatio",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes %s %q in namespace %q has %d dropped targets out of %d observed targets (ratio %.2f, threshold %.2f)", kind, target.Name, namespace, droppedCount, observedCount, ratio, defaultKubernetesRuntimeDropRatio),
			},
			Recommendation: "审查 target relabeling 是否过度过滤有效实例，并核对服务发现标签变化；Prometheus 可能限制保留的 dropped targets，因此当前比例应视为观测下界。",
			Metadata:       metadata,
			Status:         model.FindingStatusOpen,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	sortKubernetesRuntimeDropFindings(findings)
	return findings, nil
}

func kubernetesRuntimeDropCounts(target model.Resource) (active int, dropped int, observed int, ratio float64, ok bool) {
	kind := strings.TrimSpace(target.Metadata["kubernetes_kind"])
	if target.Source.System != "kubernetes" || target.Status != model.ResourceStatusActive || !isPrometheusOperatorTargetKind(kind) || target.Metadata[model.MetadataRuntimeCoverageEvaluable] != "true" {
		return 0, 0, 0, 0, false
	}
	active, activeErr := strconv.Atoi(strings.TrimSpace(target.Metadata[model.MetadataRuntimeTargetCount]))
	dropped, droppedErr := strconv.Atoi(strings.TrimSpace(target.Metadata[model.MetadataRuntimeDroppedTargetCount]))
	observed, observedErr := strconv.Atoi(strings.TrimSpace(target.Metadata[model.MetadataRuntimeObservedTargetCount]))
	ratio, ratioErr := strconv.ParseFloat(strings.TrimSpace(target.Metadata[model.MetadataRuntimeDroppedTargetRatio]), 64)
	if activeErr != nil || droppedErr != nil || observedErr != nil || observed != active+dropped {
		return 0, 0, 0, 0, false
	}
	if observed == 0 {
		return active, dropped, observed, 0, true
	}
	if ratioErr != nil {
		return 0, 0, 0, 0, false
	}
	return active, dropped, observed, ratio, true
}

func kubernetesRuntimeDropFindingMetadata(analyzerID string, target model.Resource, active int, dropped int, observed int) map[string]string {
	return map[string]string{
		"analyzer_id":                              analyzerID,
		"kubernetes_kind":                          strings.TrimSpace(target.Metadata["kubernetes_kind"]),
		"namespace":                                kubernetesResourceNamespace(target),
		"prometheus_runtime_target_count":          strconv.Itoa(active),
		"prometheus_runtime_dropped_target_count":  strconv.Itoa(dropped),
		"prometheus_runtime_observed_target_count": strconv.Itoa(observed),
	}
}

func sortKubernetesRuntimeDropFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Metadata["namespace"] != findings[j].Metadata["namespace"] {
			return findings[i].Metadata["namespace"] < findings[j].Metadata["namespace"]
		}
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
}
