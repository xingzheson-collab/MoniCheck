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
	PrometheusLargeRemoteReadFrameAnalyzerID         = "builtin.prometheus_large_remote_read_frame"
	PrometheusHighWebConnectionLimitAnalyzerID       = "builtin.prometheus_high_web_connection_limit"
	PrometheusLongWebReadTimeoutAnalyzerID           = "builtin.prometheus_long_web_read_timeout"
	prometheusDefaultRemoteReadFrameBytes      int64 = 1_048_576
	prometheusDefaultWebMaxConnections         int64 = 512
	prometheusDefaultWebReadTimeoutSeconds     int64 = 300
)

type PrometheusWebRuntimeAnalyzer struct {
	id   string
	name string
}

func NewPrometheusLargeRemoteReadFrameAnalyzer() *PrometheusWebRuntimeAnalyzer {
	return &PrometheusWebRuntimeAnalyzer{id: PrometheusLargeRemoteReadFrameAnalyzerID, name: "Prometheus Large Remote Read Frame"}
}

func NewPrometheusHighWebConnectionLimitAnalyzer() *PrometheusWebRuntimeAnalyzer {
	return &PrometheusWebRuntimeAnalyzer{id: PrometheusHighWebConnectionLimitAnalyzerID, name: "Prometheus High Web Connection Limit"}
}

func NewPrometheusLongWebReadTimeoutAnalyzer() *PrometheusWebRuntimeAnalyzer {
	return &PrometheusWebRuntimeAnalyzer{id: PrometheusLongWebReadTimeoutAnalyzerID, name: "Prometheus Long Web Read Timeout"}
}

func (a *PrometheusWebRuntimeAnalyzer) ID() string      { return a.id }
func (a *PrometheusWebRuntimeAnalyzer) Name() string    { return a.name }
func (a *PrometheusWebRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusWebRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusWebRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
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
		if a.id == PrometheusLargeRemoteReadFrameAnalyzerID &&
			resource.Metadata[model.MetadataPrometheusAgentMode] == "true" {
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

func (a *PrometheusWebRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryCost
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusLargeRemoteReadFrameAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusRemoteReadFrameBytes)
		if !ok || value <= prometheusDefaultRemoteReadFrameBytes {
			return model.Finding{}, false
		}
		findingType = "PrometheusLargeRemoteReadFrame"
		evidence = fmt.Sprintf("Prometheus streamed remote read frame limit is %d bytes, above the official 1048576-byte default", value)
		recommendation = "将 --storage.remote.read-max-bytes-in-frame 调回 1048576 字节或经过端到端容量验证的范围，并同时核对客户端 frame 限制、内存峰值和网络吞吐。"
		metadata[model.MetadataPrometheusRemoteReadFrameBytes] = strconv.FormatInt(value, 10)
	case PrometheusHighWebConnectionLimitAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusWebMaxConnections)
		if !ok || value <= prometheusDefaultWebMaxConnections {
			return model.Finding{}, false
		}
		findingType = "PrometheusHighWebConnectionLimit"
		evidence = fmt.Sprintf("Prometheus web connection limit is %d, above the official default of 512", value)
		recommendation = "将 --web.max-connections 调整为经过并发压测验证的范围，并结合文件描述符、内存、反向代理连接池和请求延迟观察容量。"
		metadata[model.MetadataPrometheusWebMaxConnections] = strconv.FormatInt(value, 10)
	case PrometheusLongWebReadTimeoutAnalyzerID:
		value, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusWebReadTimeoutSeconds)
		if !ok || value <= prometheusDefaultWebReadTimeoutSeconds {
			return model.Finding{}, false
		}
		findingType = "PrometheusLongWebReadTimeout"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Prometheus web request read timeout is %d seconds, above the official default of 300 seconds", value)
		recommendation = "将 --web.read-timeout 保持在客户端上传需求所需的最小范围，并在反向代理配置更短的 header/body timeout、认证和连接限流。"
		metadata[model.MetadataPrometheusWebReadTimeoutSeconds] = strconv.FormatInt(value, 10)
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
