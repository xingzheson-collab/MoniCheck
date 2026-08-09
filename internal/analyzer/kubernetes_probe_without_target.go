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

const KubernetesProbeWithoutTargetAnalyzerID = "builtin.kubernetes_probe_without_target"

type KubernetesProbeWithoutTargetAnalyzer struct{}

func NewKubernetesProbeWithoutTargetAnalyzer() *KubernetesProbeWithoutTargetAnalyzer {
	return &KubernetesProbeWithoutTargetAnalyzer{}
}

func (a *KubernetesProbeWithoutTargetAnalyzer) ID() string {
	return KubernetesProbeWithoutTargetAnalyzerID
}

func (a *KubernetesProbeWithoutTargetAnalyzer) Name() string {
	return "Kubernetes Probe Without Target"
}

func (a *KubernetesProbeWithoutTargetAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesProbeWithoutTargetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesProbeWithoutTargetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesProbeTarget(target) || kubernetesProbeHasTargets(target) {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		mode := strings.TrimSpace(target.Metadata["probe_target_mode"])
		count := strings.TrimSpace(target.Metadata["probe_target_count"])
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesProbeWithoutTarget",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes Probe %q in namespace %q has no effective static or ingress target configuration", target.Name, namespace),
			},
			Recommendation: "为该 Probe 配置非空 targets.staticConfig.static，或配置 targets.ingress 进行动态目标发现；没有目标时 Prometheus Operator 无法生成探测任务。",
			Metadata: map[string]string{
				"analyzer_id":        a.ID(),
				"kubernetes_kind":    "Probe",
				"namespace":          namespace,
				"probe_target_mode":  mode,
				"probe_target_count": count,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Metadata["namespace"] != findings[j].Metadata["namespace"] {
			return findings[i].Metadata["namespace"] < findings[j].Metadata["namespace"]
		}
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func isKubernetesProbeTarget(resource model.Resource) bool {
	return resource.Source.System == "kubernetes" &&
		resource.Type == model.ResourceTypeTarget &&
		resource.Status == model.ResourceStatusActive &&
		strings.TrimSpace(resource.Metadata["kubernetes_kind"]) == "Probe"
}

func kubernetesProbeHasTargets(resource model.Resource) bool {
	mode := strings.TrimSpace(resource.Metadata["probe_target_mode"])
	if mode == "ingress" {
		return true
	}
	if mode != "static" {
		return false
	}
	count, err := strconv.Atoi(strings.TrimSpace(resource.Metadata["probe_target_count"]))
	return err == nil && count > 0
}
