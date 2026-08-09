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
	PrometheusAgentWALCompressionDisabledAnalyzerID         = "builtin.prometheus_agent_wal_compression_disabled"
	PrometheusAgentLongWALRetentionAnalyzerID               = "builtin.prometheus_agent_long_wal_retention"
	PrometheusAgentLongWALMinimumRetentionAnalyzerID        = "builtin.prometheus_agent_long_wal_minimum_retention"
	PrometheusAgentShortRemoteFlushDeadlineAnalyzerID       = "builtin.prometheus_agent_short_remote_flush_deadline"
	prometheusDefaultAgentRetentionMinSeconds         int64 = 5 * 60
	prometheusDefaultAgentRetentionMaxSeconds         int64 = 4 * 60 * 60
	prometheusDefaultRemoteFlushDeadlineSeconds       int64 = 60
)

type PrometheusAgentStorageAnalyzer struct {
	id   string
	name string
}

func NewPrometheusAgentWALCompressionDisabledAnalyzer() *PrometheusAgentStorageAnalyzer {
	return &PrometheusAgentStorageAnalyzer{
		id:   PrometheusAgentWALCompressionDisabledAnalyzerID,
		name: "Prometheus Agent WAL Compression Disabled",
	}
}

func NewPrometheusAgentLongWALRetentionAnalyzer() *PrometheusAgentStorageAnalyzer {
	return &PrometheusAgentStorageAnalyzer{
		id:   PrometheusAgentLongWALRetentionAnalyzerID,
		name: "Prometheus Agent Long WAL Retention",
	}
}

func NewPrometheusAgentLongWALMinimumRetentionAnalyzer() *PrometheusAgentStorageAnalyzer {
	return &PrometheusAgentStorageAnalyzer{
		id:   PrometheusAgentLongWALMinimumRetentionAnalyzerID,
		name: "Prometheus Agent Long WAL Minimum Retention",
	}
}

func NewPrometheusAgentShortRemoteFlushDeadlineAnalyzer() *PrometheusAgentStorageAnalyzer {
	return &PrometheusAgentStorageAnalyzer{
		id:   PrometheusAgentShortRemoteFlushDeadlineAnalyzerID,
		name: "Prometheus Agent Short Remote Flush Deadline",
	}
}

func (a *PrometheusAgentStorageAnalyzer) ID() string      { return a.id }
func (a *PrometheusAgentStorageAnalyzer) Name() string    { return a.name }
func (a *PrometheusAgentStorageAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusAgentStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusAgentStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAgentMode] != "true" {
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

func (a *PrometheusAgentStorageAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryCost
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusAgentWALCompressionDisabledAnalyzerID:
		compression, ok := resource.Metadata[model.MetadataPrometheusAgentWALCompression]
		if !ok || compression != "false" {
			return model.Finding{}, false
		}
		findingType = "PrometheusAgentWALCompressionDisabled"
		evidence = "Prometheus Agent mode is enabled while Agent WAL compression is explicitly disabled"
		recommendation = "启用 --storage.agent.wal-compression，验证 CPU 余量和 remote_write 吞吐后观察 WAL 磁盘占用与写入 I/O 的下降。"
		metadata[model.MetadataPrometheusAgentWALCompression] = "false"
	case PrometheusAgentLongWALRetentionAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusAgentRetentionMaxSeconds)
		if !ok || value <= prometheusDefaultAgentRetentionMaxSeconds {
			return model.Finding{}, false
		}
		findingType = "PrometheusAgentLongWALRetention"
		evidence = fmt.Sprintf("Prometheus Agent WAL maximum retention is %d seconds, above the official default of 14400 seconds", value)
		recommendation = "将 --storage.agent.retention.max-time 调回 4h 或经过 remote_write 故障窗口与磁盘容量验证的范围，并为远端不可用场景设置磁盘水位告警。"
		metadata[model.MetadataPrometheusAgentRetentionMaxSeconds] = strconv.FormatInt(value, 10)
	case PrometheusAgentLongWALMinimumRetentionAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusAgentRetentionMinSeconds)
		if !ok || value <= prometheusDefaultAgentRetentionMinSeconds {
			return model.Finding{}, false
		}
		findingType = "PrometheusAgentLongWALMinimumRetention"
		evidence = fmt.Sprintf("Prometheus Agent WAL minimum retention is %d seconds, above the official default of 300 seconds", value)
		recommendation = "将 --storage.agent.retention.min-time 恢复到官方 5m 默认值或经过磁盘容量与 checkpoint 频率验证的范围，并观察 Agent WAL 占用和截断耗时。"
		metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = strconv.FormatInt(value, 10)
	case PrometheusAgentShortRemoteFlushDeadlineAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusRemoteFlushDeadline)
		if !ok || value <= 0 || value >= prometheusDefaultRemoteFlushDeadlineSeconds {
			return model.Finding{}, false
		}
		findingType = "PrometheusAgentShortRemoteFlushDeadline"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Prometheus Agent waits only %d seconds to flush remote-write samples on shutdown or configuration reload, below the official 60-second default", value)
		recommendation = "将 --storage.remote.flush-deadline 恢复到官方 1m 默认值或经过 remote_write backlog 演练验证的更长窗口，并确保终止宽限期覆盖完整 flush。"
		metadata[model.MetadataPrometheusRemoteFlushDeadline] = strconv.FormatInt(value, 10)
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
