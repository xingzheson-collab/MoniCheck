package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const OrphanedResourceAnalyzerID = "builtin.orphaned_resource"

type OrphanedResourceAnalyzer struct{}

func NewOrphanedResourceAnalyzer() *OrphanedResourceAnalyzer {
	return &OrphanedResourceAnalyzer{}
}

func (a *OrphanedResourceAnalyzer) ID() string      { return OrphanedResourceAnalyzerID }
func (a *OrphanedResourceAnalyzer) Name() string    { return "Orphaned Resource" }
func (a *OrphanedResourceAnalyzer) Version() string { return "0.1.0" }

func (a *OrphanedResourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric, model.ResourceTypeMetricLabel, model.ResourceTypeTSDB,
		model.ResourceTypeService, model.ResourceTypeDashboard, model.ResourceTypeFolder,
		model.ResourceTypePanel, model.ResourceTypeDatasource, model.ResourceTypeAlert,
		model.ResourceTypeAlertRule, model.ResourceTypeSilence, model.ResourceTypeReceiver, model.ResourceTypeNotificationPolicy, model.ResourceTypeInhibitionRule, model.ResourceTypeTimeInterval, model.ResourceTypeNotificationTemplate,
		model.ResourceTypeProcessor, model.ResourceTypePipeline, model.ResourceTypeExtension, model.ResourceTypeTelemetryConnector, model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget, model.ResourceTypeExporter, model.ResourceTypeJob,
		model.ResourceTypeInstance, model.ResourceTypeLogLabel, model.ResourceTypeLogLabelValue,
		model.ResourceTypeTraceTag, model.ResourceTypeTraceTagValue, model.ResourceTypeTraceOperation,
		model.ResourceTypeLogStream, model.ResourceTypeTraceService, model.ResourceTypeTable,
		model.ResourceTypeScrapeClass,
	}
}

func (a *OrphanedResourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusOrphan || derivedServiceResource(resource) {
			continue
		}
		connectorID := strings.TrimSpace(resource.Metadata[model.MetadataConnectorID])
		if connectorID == "" {
			connectorID = strings.TrimSpace(resource.Source.System)
		}
		lastSeenAt := strings.TrimSpace(resource.Metadata[model.MetadataConnectorLastSeenAt])
		orphanedAt := strings.TrimSpace(resource.Metadata[model.MetadataConnectorOrphanedAt])
		evidence := fmt.Sprintf("%s %q is ORPHAN after disappearing from connector %q", resource.Type, resource.Name, connectorID)
		if orphanedAt != "" {
			evidence += " at " + orphanedAt
		}
		metadata := map[string]string{
			"analyzer_id":     a.ID(),
			"connector_id":    connectorID,
			"source_system":   resource.Source.System,
			"source_instance": resource.Source.Instance,
		}
		if lastSeenAt != "" {
			metadata["last_seen_at"] = lastSeenAt
		}
		if orphanedAt != "" {
			metadata["orphaned_at"] = orphanedAt
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "OrphanedResource",
			Severity: model.SeverityWarning, Category: model.FindingCategoryLifecycle,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{evidence},
			Recommendation: "确认资源是否在上游被有意删除或改名；如属预期变更，清理相关配置与历史资源，否则修复 Connector 权限、发现范围或上游对象后重新同步。",
			Metadata:       metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func derivedServiceResource(resource model.Resource) bool {
	return resource.Type == model.ResourceTypeService && resource.Source.System == "monicheck" && resource.Metadata["derived"] == "true"
}
