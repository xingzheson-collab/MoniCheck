package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	TSDBGrowthAnalyzerID                  = "builtin.tsdb_growth"
	defaultTSDBGrowthLookback             = 7 * 24 * time.Hour
	defaultTSDBSeriesGrowthRatioThreshold = 0.20
	defaultTSDBSeriesGrowthMinimum        = 100000
	defaultTSDBMemoryGrowthRatioThreshold = 0.20
	defaultTSDBMemoryGrowthMinimumBytes   = 10 * 1024 * 1024
)

type TSDBGrowthAnalyzer struct{}

func NewTSDBGrowthAnalyzer() *TSDBGrowthAnalyzer { return &TSDBGrowthAnalyzer{} }
func (a *TSDBGrowthAnalyzer) ID() string         { return TSDBGrowthAnalyzerID }
func (a *TSDBGrowthAnalyzer) Name() string       { return "TSDB Growth" }
func (a *TSDBGrowthAnalyzer) Version() string    { return "0.1.0" }
func (a *TSDBGrowthAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *TSDBGrowthAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.ReportExports == nil {
		return nil, nil
	}
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	lookback := durationConfig(analysis.Config, "tsdb_growth_lookback", defaultTSDBGrowthLookback)
	baseline, baselineAt, err := latestTSDBCostBaseline(ctx, analysis.ReportExports, time.Now().UTC().Add(-lookback))
	if err != nil || len(baseline) == 0 {
		return nil, err
	}

	seriesRatioThreshold := floatConfig(analysis.Config, "tsdb_series_growth_ratio_threshold", defaultTSDBSeriesGrowthRatioThreshold)
	seriesMinimum := int64(intConfig(analysis.Config, "tsdb_series_growth_minimum", defaultTSDBSeriesGrowthMinimum))
	memoryRatioThreshold := floatConfig(analysis.Config, "tsdb_label_memory_growth_ratio_threshold", defaultTSDBMemoryGrowthRatioThreshold)
	memoryMinimum := int64(intConfig(analysis.Config, "tsdb_label_memory_growth_minimum_bytes", defaultTSDBMemoryGrowthMinimumBytes))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		previous, ok := baseline[tsdbGrowthResourceKey(resource)]
		if !ok {
			previous, ok = baseline[tsdbGrowthSourceKey(resource.Source.System, resource.Source.Instance)]
		}
		if !ok {
			continue
		}
		currentSeries, _ := positiveMetadataInt64(resource, model.MetadataTSDBHeadSeries)
		currentMemory, _ := positiveMetadataInt64(resource, model.MetadataTSDBLabelMemoryBytes)
		seriesGrowth := tsdbGrowth(currentSeries, previous.HeadSeries, seriesRatioThreshold, seriesMinimum)
		memoryGrowth := tsdbGrowth(currentMemory, previous.LabelMemoryBytes, memoryRatioThreshold, memoryMinimum)
		if !seriesGrowth.Exceeded && !memoryGrowth.Exceeded {
			continue
		}
		evidence := make([]string, 0, 2)
		if seriesGrowth.Exceeded {
			evidence = append(evidence, fmt.Sprintf("TSDB Head series grew from %d to %d (+%d, %.1f%%) since %s", previous.HeadSeries, currentSeries, seriesGrowth.Delta, seriesGrowth.Ratio*100, baselineAt.Format(time.RFC3339)))
		}
		if memoryGrowth.Exceeded {
			evidence = append(evidence, fmt.Sprintf("TSDB label memory grew from %d to %d bytes (+%d, %.1f%%) since %s", previous.LabelMemoryBytes, currentMemory, memoryGrowth.Delta, memoryGrowth.Ratio*100, baselineAt.Format(time.RFC3339)))
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), resource.ID),
			Type:           "RapidTSDBGrowth",
			Severity:       model.SeverityWarning,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       evidence,
			Recommendation: "对比最近部署、采集目标和 label 变更，定位新增高基数指标或长字符串标签；确认增长符合容量计划，否则回滚或增加采集过滤。",
			Metadata: map[string]string{
				"analyzer_id":                 a.ID(),
				"baseline_at":                 baselineAt.Format(time.RFC3339),
				"previous_head_series":        strconv.FormatInt(previous.HeadSeries, 10),
				"current_head_series":         strconv.FormatInt(currentSeries, 10),
				"series_growth_delta":         strconv.FormatInt(seriesGrowth.Delta, 10),
				"series_growth_ratio":         strconv.FormatFloat(seriesGrowth.Ratio, 'f', 6, 64),
				"previous_label_memory_bytes": strconv.FormatInt(previous.LabelMemoryBytes, 10),
				"current_label_memory_bytes":  strconv.FormatInt(currentMemory, 10),
				"label_memory_growth_delta":   strconv.FormatInt(memoryGrowth.Delta, 10),
				"label_memory_growth_ratio":   strconv.FormatFloat(memoryGrowth.Ratio, 'f', 6, 64),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.Name < findings[j].Resource.Name })
	return findings, nil
}

type tsdbGrowthBaseline struct {
	ID               string `json:"id"`
	System           string `json:"system"`
	Instance         string `json:"instance"`
	HeadSeries       int64  `json:"head_series"`
	LabelMemoryBytes int64  `json:"label_memory_bytes"`
}

func latestTSDBCostBaseline(ctx context.Context, repository storage.ReportExportRepository, since time.Time) (map[string]tsdbGrowthBaseline, time.Time, error) {
	exports, err := repository.List(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	sort.Slice(exports, func(i, j int) bool { return exports[i].CreatedAt.After(exports[j].CreatedAt) })
	for _, export := range exports {
		if export.Type != "cost" || export.Format != "json" || export.CreatedAt.Before(since) {
			continue
		}
		var payload struct {
			Instances []tsdbGrowthBaseline `json:"tsdb_instances"`
		}
		if err := json.Unmarshal([]byte(export.Content), &payload); err != nil || len(payload.Instances) == 0 {
			continue
		}
		baseline := make(map[string]tsdbGrowthBaseline, len(payload.Instances)*2)
		for _, item := range payload.Instances {
			if strings.TrimSpace(item.ID) != "" {
				baseline["id:"+strings.TrimSpace(item.ID)] = item
			}
			if key := tsdbGrowthSourceKey(item.System, item.Instance); key != "source:\x00" {
				baseline[key] = item
			}
		}
		if len(baseline) > 0 {
			return baseline, export.CreatedAt, nil
		}
	}
	return nil, time.Time{}, nil
}

type tsdbGrowthResult struct {
	Delta    int64
	Ratio    float64
	Exceeded bool
}

func tsdbGrowth(current int64, previous int64, ratioThreshold float64, minimum int64) tsdbGrowthResult {
	if current <= previous || previous <= 0 {
		return tsdbGrowthResult{}
	}
	delta := current - previous
	ratio := float64(delta) / float64(previous)
	return tsdbGrowthResult{Delta: delta, Ratio: ratio, Exceeded: delta >= minimum && ratio >= ratioThreshold}
}

func tsdbGrowthResourceKey(resource model.Resource) string {
	return "id:" + strings.TrimSpace(resource.ID)
}

func tsdbGrowthSourceKey(system string, instance string) string {
	return "source:" + strings.TrimSpace(system) + "\x00" + strings.TrimSpace(instance)
}
