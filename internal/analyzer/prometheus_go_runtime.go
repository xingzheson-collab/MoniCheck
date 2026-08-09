package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusAutoGOMAXPROCSDisabledAnalyzerID  = "builtin.prometheus_auto_gomaxprocs_disabled"
	PrometheusAutoGOMEMLIMITDisabledAnalyzerID  = "builtin.prometheus_auto_gomemlimit_disabled"
	PrometheusHighAutoGOMEMLIMITRatioAnalyzerID = "builtin.prometheus_high_auto_gomemlimit_ratio"
	prometheusDefaultAutoGOMEMLIMITRatio        = 0.9
)

type PrometheusGoRuntimeAnalyzer struct {
	id   string
	name string
}

func NewPrometheusAutoGOMAXPROCSDisabledAnalyzer() *PrometheusGoRuntimeAnalyzer {
	return &PrometheusGoRuntimeAnalyzer{id: PrometheusAutoGOMAXPROCSDisabledAnalyzerID, name: "Prometheus Auto GOMAXPROCS Disabled"}
}

func NewPrometheusAutoGOMEMLIMITDisabledAnalyzer() *PrometheusGoRuntimeAnalyzer {
	return &PrometheusGoRuntimeAnalyzer{id: PrometheusAutoGOMEMLIMITDisabledAnalyzerID, name: "Prometheus Auto GOMEMLIMIT Disabled"}
}

func NewPrometheusHighAutoGOMEMLIMITRatioAnalyzer() *PrometheusGoRuntimeAnalyzer {
	return &PrometheusGoRuntimeAnalyzer{id: PrometheusHighAutoGOMEMLIMITRatioAnalyzerID, name: "Prometheus High Auto GOMEMLIMIT Ratio"}
}

func (a *PrometheusGoRuntimeAnalyzer) ID() string      { return a.id }
func (a *PrometheusGoRuntimeAnalyzer) Name() string    { return a.name }
func (a *PrometheusGoRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusGoRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusGoRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusGoRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryReliability
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusAutoGOMAXPROCSDisabledAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusAutoGOMAXPROCSEnabled] != "false" {
			return model.Finding{}, false
		}
		findingType = "PrometheusAutoGOMAXPROCSDisabled"
		category = model.FindingCategoryCost
		evidence = "Prometheus automatic GOMAXPROCS adjustment is explicitly disabled"
		recommendation = "启用 --auto-gomaxprocs，使 Prometheus 按 Linux 容器 CPU quota 调整 Go 调度并发；随后观察 CPU throttling、规则评估和查询延迟。"
		metadata[model.MetadataPrometheusAutoGOMAXPROCSEnabled] = "false"
	case PrometheusAutoGOMEMLIMITDisabledAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusAutoGOMEMLIMITEnabled] != "false" {
			return model.Finding{}, false
		}
		findingType = "PrometheusAutoGOMEMLIMITDisabled"
		evidence = "Prometheus automatic GOMEMLIMIT adjustment is explicitly disabled"
		recommendation = "启用 --auto-gomemlimit，使 Prometheus 根据 Linux 容器或系统内存限制设置 Go 内存上限；随后验证 GC、查询峰值、head series 和 OOM 行为。"
		metadata[model.MetadataPrometheusAutoGOMEMLIMITEnabled] = "false"
	case PrometheusHighAutoGOMEMLIMITRatioAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusAutoGOMEMLIMITEnabled] != "true" {
			return model.Finding{}, false
		}
		ratio, err := strconv.ParseFloat(resource.Metadata[model.MetadataPrometheusAutoGOMEMLIMITRatio], 64)
		if err != nil || ratio <= prometheusDefaultAutoGOMEMLIMITRatio {
			return model.Finding{}, false
		}
		findingType = "PrometheusHighAutoGOMEMLIMITRatio"
		evidence = fmt.Sprintf("Prometheus automatic GOMEMLIMIT ratio is %s, above the official default of 0.9", strconv.FormatFloat(ratio, 'f', -1, 64))
		recommendation = "将 --auto-gomemlimit.ratio 恢复到官方 0.9 默认值或经过峰值内存压测验证的更低比例，为 Go runtime 之外的映射、栈和进程开销保留余量。"
		metadata[model.MetadataPrometheusAutoGOMEMLIMITRatio] = strconv.FormatFloat(ratio, 'f', -1, 64)
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       category,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
