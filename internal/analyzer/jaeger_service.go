package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	JaegerOperationDiscoveryTruncatedAnalyzerID  = "builtin.jaeger_operation_discovery_truncated"
	JaegerDependencyDiscoveryTruncatedAnalyzerID = "builtin.jaeger_dependency_discovery_truncated"
)

type JaegerOperationDiscoveryTruncatedAnalyzer struct{}

func NewJaegerOperationDiscoveryTruncatedAnalyzer() *JaegerOperationDiscoveryTruncatedAnalyzer {
	return &JaegerOperationDiscoveryTruncatedAnalyzer{}
}

type JaegerDependencyDiscoveryTruncatedAnalyzer struct{}

func NewJaegerDependencyDiscoveryTruncatedAnalyzer() *JaegerDependencyDiscoveryTruncatedAnalyzer {
	return &JaegerDependencyDiscoveryTruncatedAnalyzer{}
}

func (a *JaegerDependencyDiscoveryTruncatedAnalyzer) ID() string {
	return JaegerDependencyDiscoveryTruncatedAnalyzerID
}

func (a *JaegerDependencyDiscoveryTruncatedAnalyzer) Name() string {
	return "Jaeger Dependency Discovery Truncated"
}

func (a *JaegerDependencyDiscoveryTruncatedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *JaegerDependencyDiscoveryTruncatedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService}
}

func (a *JaegerDependencyDiscoveryTruncatedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	servicesByInstance := make(map[string][]model.Resource)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive ||
			service.Source.System != "jaeger" ||
			service.Metadata[model.MetadataAPMTopologyDiscoveryAvailable] != "true" ||
			service.Metadata[model.MetadataAPMTopologyDiscoveryTruncated] != "true" {
			continue
		}
		servicesByInstance[service.Source.Instance] = append(servicesByInstance[service.Source.Instance], service)
	}
	instances := make([]string, 0, len(servicesByInstance))
	for instance := range servicesByInstance {
		instances = append(instances, instance)
	}
	sort.Strings(instances)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0, len(instances))
	for _, instance := range instances {
		instanceServices := servicesByInstance[instance]
		sortResourcesByTypeAndName(instanceServices)
		primary := instanceServices[0]
		count := primary.Metadata[model.MetadataAPMTopologyDependencyCount]
		limit := primary.Metadata[model.MetadataAPMTopologyDependencyLimit]
		lookback := primary.Metadata[model.MetadataAPMLookback]
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), instance),
			Type:     "JaegerDependencyDiscoveryTruncated",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: primary.ID, Type: primary.Type, Name: primary.Name},
			Evidence: []string{
				fmt.Sprintf("Jaeger dependency discovery returned %s unique service edges for lookback %s and retained only %s", count, lookback, limit),
				"service dependency impact, fanout, and cycle analysis currently operate on an incomplete graph",
			},
			Recommendation: "先检查 dependency 聚合任务的时间窗口与服务基数，再缩短 jaeger_dependency_lookback 或提高经容量评估的 jaeger_dependency_limit；重新同步后确认拓扑不再截断。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"count":       count,
				"limit":       limit,
				"lookback":    lookback,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func (a *JaegerOperationDiscoveryTruncatedAnalyzer) ID() string {
	return JaegerOperationDiscoveryTruncatedAnalyzerID
}

func (a *JaegerOperationDiscoveryTruncatedAnalyzer) Name() string {
	return "Jaeger Operation Discovery Truncated"
}

func (a *JaegerOperationDiscoveryTruncatedAnalyzer) Version() string {
	return "0.1.0"
}

func (a *JaegerOperationDiscoveryTruncatedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService, model.ResourceTypeTraceOperation}
}

func (a *JaegerOperationDiscoveryTruncatedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive ||
			service.Source.System != "jaeger" ||
			service.Metadata[model.MetadataOperationDiscoveryAvailable] != "true" ||
			service.Metadata[model.MetadataOperationDiscoveryTruncated] != "true" {
			continue
		}
		count := service.Metadata[model.MetadataOperationCount]
		limit := service.Metadata[model.MetadataOperationLimit]
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "JaegerOperationDiscoveryTruncated",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("Jaeger service %q exposes %s unique operation names and retained only the first %s in deterministic order", service.Name, count, limit),
				"Jaeger operation discovery has no server-side pagination or limit, so the retained graph is incomplete for this service",
			},
			Recommendation: "检查 operation 名称是否包含动态 ID、原始 URL 或载荷片段；修复高基数命名后重新同步，或在确认资源规模可控时调高 jaeger_operation_limit。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"count":       count,
				"limit":       limit,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
