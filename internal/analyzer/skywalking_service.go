package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	SkyWalkingServiceWithoutInstanceAnalyzerID     = "builtin.skywalking_service_without_instance"
	SkyWalkingEndpointDiscoveryTruncatedAnalyzerID = "builtin.skywalking_endpoint_discovery_truncated"
	SkyWalkingServiceAlarmBurstAnalyzerID          = "builtin.skywalking_service_alarm_burst"
	defaultSkyWalkingActiveAlarmThreshold          = 5
)

type SkyWalkingServiceWithoutInstanceAnalyzer struct{}

func NewSkyWalkingServiceWithoutInstanceAnalyzer() *SkyWalkingServiceWithoutInstanceAnalyzer {
	return &SkyWalkingServiceWithoutInstanceAnalyzer{}
}

type SkyWalkingServiceAlarmBurstAnalyzer struct{}

func NewSkyWalkingServiceAlarmBurstAnalyzer() *SkyWalkingServiceAlarmBurstAnalyzer {
	return &SkyWalkingServiceAlarmBurstAnalyzer{}
}

func (a *SkyWalkingServiceAlarmBurstAnalyzer) ID() string {
	return SkyWalkingServiceAlarmBurstAnalyzerID
}

func (a *SkyWalkingServiceAlarmBurstAnalyzer) Name() string {
	return "SkyWalking Service Alarm Burst"
}

func (a *SkyWalkingServiceAlarmBurstAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SkyWalkingServiceAlarmBurstAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService, model.ResourceTypeAlert}
}

func (a *SkyWalkingServiceAlarmBurstAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	threshold := intConfig(analysis.Config, "skywalking_active_alarm_threshold", defaultSkyWalkingActiveAlarmThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive || service.Source.System != "skywalking" ||
			service.Metadata[model.MetadataAPMAlarmDiscoveryAvailable] != "true" {
			continue
		}
		activeCount, err := strconv.Atoi(service.Metadata[model.MetadataAPMActiveAlarmCount])
		if err != nil || activeCount <= threshold {
			continue
		}
		countQualifier := ""
		if service.Metadata[model.MetadataAPMAlarmDiscoveryTruncated] == "true" {
			countQualifier = "at least "
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "SkyWalkingServiceAlarmBurst",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("SkyWalking service %q has %s%d active alarms in the configured observation window; threshold is %d", service.Name, countQualifier, activeCount, threshold),
				fmt.Sprintf("alarm discovery completed successfully with total_alarm_count=%s and recovered_alarm_count=%s", service.Metadata[model.MetadataAPMAlarmCount], service.Metadata[model.MetadataAPMRecoveredAlarmCount]),
			},
			Recommendation: "检查该服务近期是否发生级联故障、重复规则或阈值过敏；合并同根因告警并确认服务依赖、实例和端点层告警是否重复放大。",
			Metadata: map[string]string{
				"analyzer_id":        a.ID(),
				"active_alarm_count": strconv.Itoa(activeCount),
				"threshold":          strconv.Itoa(threshold),
				"count_truncated":    service.Metadata[model.MetadataAPMAlarmDiscoveryTruncated],
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func (a *SkyWalkingServiceWithoutInstanceAnalyzer) ID() string {
	return SkyWalkingServiceWithoutInstanceAnalyzerID
}

func (a *SkyWalkingServiceWithoutInstanceAnalyzer) Name() string {
	return "SkyWalking Service Without Instance"
}

func (a *SkyWalkingServiceWithoutInstanceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SkyWalkingServiceWithoutInstanceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService, model.ResourceTypeInstance}
}

func (a *SkyWalkingServiceWithoutInstanceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive || service.Source.System != "skywalking" ||
			service.Metadata[model.MetadataAPMCatalogService] != "true" ||
			service.Metadata[model.MetadataAPMInstanceDiscoveryAvailable] != "true" ||
			service.Metadata[model.MetadataAPMInstanceCount] != "0" ||
			strings.EqualFold(service.Metadata[model.MetadataAPMNormal], "false") {
			continue
		}
		lookback := strings.TrimSpace(service.Metadata[model.MetadataAPMLookback])
		if lookback == "" {
			lookback = "the configured observation window"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "SkyWalkingServiceWithoutInstance",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("SkyWalking service %q has no active service instance in %s", service.Name, lookback),
				"instance discovery completed successfully with instance_count=0",
			},
			Recommendation: "确认服务是否已下线；若仍在运行，检查 SkyWalking agent 注册、服务名配置、OAP 连通性和实例心跳。已下线服务应从治理范围中归档，避免陈旧 APM 目录持续存在。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"instance_count": "0",
				"lookback":       lookback,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

type SkyWalkingEndpointDiscoveryTruncatedAnalyzer struct{}

func NewSkyWalkingEndpointDiscoveryTruncatedAnalyzer() *SkyWalkingEndpointDiscoveryTruncatedAnalyzer {
	return &SkyWalkingEndpointDiscoveryTruncatedAnalyzer{}
}

func (a *SkyWalkingEndpointDiscoveryTruncatedAnalyzer) ID() string {
	return SkyWalkingEndpointDiscoveryTruncatedAnalyzerID
}

func (a *SkyWalkingEndpointDiscoveryTruncatedAnalyzer) Name() string {
	return "SkyWalking Endpoint Discovery Truncated"
}

func (a *SkyWalkingEndpointDiscoveryTruncatedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SkyWalkingEndpointDiscoveryTruncatedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService, model.ResourceTypeTraceOperation}
}

func (a *SkyWalkingEndpointDiscoveryTruncatedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive || service.Source.System != "skywalking" ||
			service.Metadata[model.MetadataAPMEndpointDiscoveryTruncated] != "true" {
			continue
		}
		count := service.Metadata[model.MetadataAPMEndpointCount]
		limit := service.Metadata[model.MetadataAPMEndpointLimit]
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "SkyWalkingEndpointDiscoveryTruncated",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("SkyWalking returned %s endpoints for service %q, reaching the configured limit %s", count, service.Name, limit),
				"the endpoint catalog may be incomplete; snapshot reconciliation remains non-destructive",
			},
			Recommendation: "检查该服务是否存在未参数化 URL、动态 RPC 方法或其他端点基数膨胀；治理后缩小端点数量，或在确认容量影响后提高 skywalking_endpoint_limit。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"endpoint_count": count,
				"endpoint_limit": limit,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
