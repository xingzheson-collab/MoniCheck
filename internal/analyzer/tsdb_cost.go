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
	HighSeriesTSDBAnalyzerID        = "builtin.high_series_tsdb"
	HighTSDBLabelMemoryAnalyzerID   = "builtin.high_tsdb_label_memory"
	defaultTSDBHeadSeriesThreshold  = 1000000
	defaultTSDBLabelMemoryThreshold = 100 * 1024 * 1024
)

type HighSeriesTSDBAnalyzer struct{}

func NewHighSeriesTSDBAnalyzer() *HighSeriesTSDBAnalyzer { return &HighSeriesTSDBAnalyzer{} }
func (a *HighSeriesTSDBAnalyzer) ID() string             { return HighSeriesTSDBAnalyzerID }
func (a *HighSeriesTSDBAnalyzer) Name() string           { return "High Series TSDB" }
func (a *HighSeriesTSDBAnalyzer) Version() string        { return "0.1.0" }
func (a *HighSeriesTSDBAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *HighSeriesTSDBAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	threshold := int64(intConfig(analysis.Config, "tsdb_head_series_threshold", defaultTSDBHeadSeriesThreshold))
	return tsdbCostFindings(resources, a.ID(), "HighSeriesTSDB", model.MetadataTSDBHeadSeries, threshold,
		func(resource model.Resource, value int64) string {
			return fmt.Sprintf("TSDB %q has %d series in the Head block, threshold is %d", resource.Name, value, threshold)
		},
		"审查高基数指标和标签，删除无用时序，并通过 recording rules、采集过滤或标签规范控制 TSDB Head series 总量。"), nil
}

type HighTSDBLabelMemoryAnalyzer struct{}

func NewHighTSDBLabelMemoryAnalyzer() *HighTSDBLabelMemoryAnalyzer {
	return &HighTSDBLabelMemoryAnalyzer{}
}
func (a *HighTSDBLabelMemoryAnalyzer) ID() string      { return HighTSDBLabelMemoryAnalyzerID }
func (a *HighTSDBLabelMemoryAnalyzer) Name() string    { return "High TSDB Label Memory" }
func (a *HighTSDBLabelMemoryAnalyzer) Version() string { return "0.1.0" }
func (a *HighTSDBLabelMemoryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *HighTSDBLabelMemoryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	threshold := int64(intConfig(analysis.Config, "tsdb_label_memory_bytes_threshold", defaultTSDBLabelMemoryThreshold))
	return tsdbCostFindings(resources, a.ID(), "HighTSDBLabelMemory", model.MetadataTSDBLabelMemoryBytes, threshold,
		func(resource model.Resource, value int64) string {
			return fmt.Sprintf("TSDB %q uses %d bytes of label-value text in the Head block, threshold is %d bytes", resource.Name, value, threshold)
		},
		"优先治理高内存 MetricLabel，缩短长字符串值并清理 UUID、完整 URL、请求标识等无界标签。"), nil
}

func tsdbCostFindings(resources []model.Resource, analyzerID string, findingType string, metadataKey string, threshold int64, evidence func(model.Resource, int64) string, recommendation string) []model.Finding {
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		value, ok := positiveMetadataInt64(resource, metadataKey)
		if !ok || value <= threshold {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(analyzerID, resource.ID),
			Type:           findingType,
			Severity:       model.SeverityWarning,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{evidence(resource, value)},
			Recommendation: recommendation,
			Metadata: map[string]string{
				"analyzer_id": analyzerID,
				"value":       strconv.FormatInt(value, 10),
				"threshold":   strconv.FormatInt(threshold, 10),
				"metric":      metadataKey,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.Name < findings[j].Resource.Name })
	return findings
}

func positiveMetadataInt64(resource model.Resource, key string) (int64, bool) {
	value := strings.TrimSpace(resource.Metadata[key])
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed > 0
}
