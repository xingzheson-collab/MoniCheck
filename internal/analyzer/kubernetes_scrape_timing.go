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
	KubernetesInvalidScrapeTimingAnalyzerID          = "builtin.kubernetes_invalid_scrape_timing"
	KubernetesScrapeTimeoutExceedsIntervalAnalyzerID = "builtin.kubernetes_scrape_timeout_exceeds_interval"
)

type KubernetesInvalidScrapeTimingAnalyzer struct{}
type KubernetesScrapeTimeoutExceedsIntervalAnalyzer struct{}

func NewKubernetesInvalidScrapeTimingAnalyzer() *KubernetesInvalidScrapeTimingAnalyzer {
	return &KubernetesInvalidScrapeTimingAnalyzer{}
}

func NewKubernetesScrapeTimeoutExceedsIntervalAnalyzer() *KubernetesScrapeTimeoutExceedsIntervalAnalyzer {
	return &KubernetesScrapeTimeoutExceedsIntervalAnalyzer{}
}

func (a *KubernetesInvalidScrapeTimingAnalyzer) ID() string {
	return KubernetesInvalidScrapeTimingAnalyzerID
}
func (a *KubernetesInvalidScrapeTimingAnalyzer) Name() string {
	return "Kubernetes Invalid Scrape Timing"
}
func (a *KubernetesInvalidScrapeTimingAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidScrapeTimingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB, model.ResourceTypeTarget}
}
func (a *KubernetesInvalidScrapeTimingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesScrapeTimingFindings(ctx, analysis, a.ID())
}

func (a *KubernetesScrapeTimeoutExceedsIntervalAnalyzer) ID() string {
	return KubernetesScrapeTimeoutExceedsIntervalAnalyzerID
}
func (a *KubernetesScrapeTimeoutExceedsIntervalAnalyzer) Name() string {
	return "Kubernetes Scrape Timeout Exceeds Interval"
}
func (a *KubernetesScrapeTimeoutExceedsIntervalAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesScrapeTimeoutExceedsIntervalAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB, model.ResourceTypeTarget}
}
func (a *KubernetesScrapeTimeoutExceedsIntervalAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesScrapeTimingFindings(ctx, analysis, a.ID())
}

func kubernetesScrapeTimingFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive {
			continue
		}
		finding, matched := kubernetesScrapeTimingFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesScrapeTimingFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	isWorkload := resource.Type == model.ResourceTypeTSDB && (kind == "Prometheus" || kind == "PrometheusAgent")
	isMonitor := resource.Type == model.ResourceTypeTarget && isKubernetesIngestionMonitorKind(kind)
	if !isWorkload && !isMonitor {
		return model.Finding{}, false
	}
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": resource.Metadata["namespace"]}
	findingType := ""
	evidence := ""
	recommendation := ""
	switch analyzerID {
	case KubernetesInvalidScrapeTimingAnalyzerID:
		key := "monitor_scrape_timing_invalid_setting_count"
		if isWorkload {
			key = "prometheus_scrape_timing_invalid_setting_count"
		}
		count := scrapeTimingMetadataInt(resource, key)
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidScrapeTiming"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid scrape interval/timeout setting(s)", kind, resource.Name, count)
		recommendation = "将 scrapeInterval/interval 和 scrapeTimeout 修正为可解析的正 Prometheus duration，例如 30s、1m 或 1h。"
		metadata["invalid_setting_count"] = strconv.Itoa(count)
	case KubernetesScrapeTimeoutExceedsIntervalAnalyzerID:
		localCount := 0
		inheritedCount := 0
		if isWorkload {
			if !strings.EqualFold(resource.Metadata["prometheus_scrape_timeout_exceeds_interval"], "true") {
				return model.Finding{}, false
			}
			localCount = 1
		} else {
			localCount = scrapeTimingMetadataInt(resource, "monitor_scrape_timeout_exceeds_interval_count")
			inheritedCount = scrapeTimingMetadataInt(resource, "prometheus_scrape_timeout_conflict_count")
			if localCount+inheritedCount == 0 {
				return model.Finding{}, false
			}
		}
		findingType = "KubernetesScrapeTimeoutExceedsInterval"
		evidence = fmt.Sprintf("Kubernetes %s %q has %d local and %d selected-workload scrape timeout/interval conflict(s)", kind, resource.Name, localCount, inheritedCount)
		recommendation = "将每个显式 scrapeTimeout 调整为不大于其局部 interval；未配置局部 interval 时，确保它不大于所有选中 Prometheus/Agent 的全局 scrapeInterval。"
		metadata["local_conflict_count"] = strconv.Itoa(localCount)
		metadata["selected_workload_conflict_count"] = strconv.Itoa(inheritedCount)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: model.SeverityCritical, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func scrapeTimingMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil {
		return 0
	}
	return value
}
