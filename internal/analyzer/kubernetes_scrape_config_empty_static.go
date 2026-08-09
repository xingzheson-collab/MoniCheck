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

const KubernetesScrapeConfigEmptyStaticAnalyzerID = "builtin.kubernetes_scrape_config_empty_static"

type KubernetesScrapeConfigEmptyStaticAnalyzer struct{}

func NewKubernetesScrapeConfigEmptyStaticAnalyzer() *KubernetesScrapeConfigEmptyStaticAnalyzer {
	return &KubernetesScrapeConfigEmptyStaticAnalyzer{}
}

func (a *KubernetesScrapeConfigEmptyStaticAnalyzer) ID() string {
	return KubernetesScrapeConfigEmptyStaticAnalyzerID
}

func (a *KubernetesScrapeConfigEmptyStaticAnalyzer) Name() string {
	return "Kubernetes ScrapeConfig Empty Static Config"
}

func (a *KubernetesScrapeConfigEmptyStaticAnalyzer) Version() string {
	return "0.1.0"
}

func (a *KubernetesScrapeConfigEmptyStaticAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTarget}
}

func (a *KubernetesScrapeConfigEmptyStaticAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	targets, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTarget})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, target := range targets {
		if !isKubernetesScrapeConfigTarget(target) {
			continue
		}
		emptyCount, err := strconv.Atoi(strings.TrimSpace(target.Metadata["scrape_config_empty_static_count"]))
		if err != nil || emptyCount <= 0 {
			continue
		}
		staticCount := strings.TrimSpace(target.Metadata["scrape_config_static_count"])
		namespace := kubernetesResourceNamespace(target)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), target.ID),
			Type:     "KubernetesScrapeConfigEmptyStatic",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryConfiguration,
			Resource: model.ResourceRef{ID: target.ID, Type: target.Type, Name: target.Name},
			Evidence: []string{
				fmt.Sprintf("Kubernetes ScrapeConfig %q in namespace %q contains %d empty static config(s) out of %s", target.Name, namespace, emptyCount, staticCount),
			},
			Recommendation: "删除空的 staticConfigs 条目或补充 targets；保留空条目会掩盖清单生成错误，并让预期 exporter 未被 Prometheus 采集。",
			Metadata: map[string]string{
				"analyzer_id":                      a.ID(),
				"kubernetes_kind":                  "ScrapeConfig",
				"namespace":                        namespace,
				"scrape_config_static_count":       staticCount,
				"scrape_config_empty_static_count": strconv.Itoa(emptyCount),
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
