package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const KubernetesProbeWithoutProberAnalyzerID = "builtin.kubernetes_probe_without_prober"

type KubernetesProbeWithoutProberAnalyzer struct{}

func NewKubernetesProbeWithoutProberAnalyzer() *KubernetesProbeWithoutProberAnalyzer {
	return &KubernetesProbeWithoutProberAnalyzer{}
}

func (a *KubernetesProbeWithoutProberAnalyzer) ID() string {
	return KubernetesProbeWithoutProberAnalyzerID
}

func (a *KubernetesProbeWithoutProberAnalyzer) Name() string {
	return "Kubernetes Probe Without Prober"
}

func (a *KubernetesProbeWithoutProberAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesProbeWithoutProberAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesProbeWithoutProberAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesProbeTarget(target) || strings.TrimSpace(target.Metadata["probe_prober_url"]) != "" {
			continue
		}
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesProbeWithoutProber",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes Probe %q in namespace %q has no prober URL", target.Name, namespace),
			},
			Recommendation: "为该 Probe 配置 spec.prober.url，并确认地址指向可访问的 blackbox exporter 或兼容 prober；缺少 prober 时所有目标都无法执行探测。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"kubernetes_kind": "Probe",
				"namespace":       namespace,
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
