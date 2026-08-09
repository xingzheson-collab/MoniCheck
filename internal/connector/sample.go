package connector

import (
	"context"
	"time"

	"monicheck/internal/model"
)

type SampleConnector struct{}

func NewSampleConnector() *SampleConnector {
	return &SampleConnector{}
}

func (c *SampleConnector) ID() string {
	return "sample"
}

func (c *SampleConnector) Name() string {
	return "Sample Connector"
}

func (c *SampleConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()

	apiMetric := resource(model.ResourceTypeMetric, "http_requests_total", "prometheus", "local", "metric:http_requests_total", now)
	cpuMetric := resource(model.ResourceTypeMetric, "node_cpu_seconds_total", "prometheus", "local", "metric:node_cpu_seconds_total", now)
	unusedMetric := resource(model.ResourceTypeMetric, "legacy_worker_queue_depth", "prometheus", "local", "metric:legacy_worker_queue_depth", now)
	dashboard := resource(model.ResourceTypeDashboard, "API Overview", "grafana", "local", "dashboard:api-overview", now)
	panel := resource(model.ResourceTypePanel, "Request Rate", "grafana", "local", "panel:api-overview:1", now)
	datasource := resource(model.ResourceTypeDatasource, "Prometheus Local", "grafana", "local", "datasource:prometheus-local", now)
	target := resource(model.ResourceTypeTarget, "http://10.0.0.2:9100/metrics", "prometheus", "local", "target:http://10.0.0.2:9100/metrics", now)
	apiMetric.Labels[model.MetadataService] = "api"
	apiMetric.Labels["team"] = "api-platform"
	apiMetric.Labels["project"] = "commerce"
	apiMetric.Labels["namespace"] = "production"
	cpuMetric.Labels["team"] = "platform"
	cpuMetric.Labels["project"] = "shared-infrastructure"
	cpuMetric.Labels["namespace"] = "monitoring"
	dashboard.Labels[model.MetadataService] = "api"
	panel.Labels[model.MetadataService] = "api"
	target.Labels[model.MetadataService] = "api"

	panel.Metadata = map[string]string{
		model.MetadataPromQL:       "sum(rate(http_requests_total[5m]))",
		model.MetadataDashboardUID: "api-overview",
		model.MetadataPanelID:      "1",
	}
	datasource.Metadata = map[string]string{
		model.MetadataDatasourceType: "prometheus",
		model.MetadataDatasourceURL:  "http://localhost:9090",
	}
	apiMetric.Metadata = map[string]string{
		model.MetadataDescription:       "HTTP request counter used by API dashboards",
		model.MetadataMetricType:        "counter",
		model.MetadataMetricHelp:        "Total HTTP requests handled by the API service.",
		model.MetadataMetricUnit:        "total",
		model.MetadataSeriesCount:       "12500",
		model.MetadataSeriesCountSource: "tsdb_head",
	}
	cpuMetric.Metadata = map[string]string{
		model.MetadataDescription:       "Node CPU counter kept for future host analyzers",
		model.MetadataMetricType:        "counter",
		model.MetadataSeriesCount:       "24000",
		model.MetadataSeriesCountSource: "tsdb_head",
	}
	unusedMetric.Metadata = map[string]string{
		model.MetadataDescription:       "Legacy metric intentionally unused in the sample dataset",
		model.MetadataSeriesCount:       "3500",
		model.MetadataSeriesCountSource: "tsdb_head",
	}
	target.Metadata = map[string]string{
		model.MetadataHealth:    "down",
		model.MetadataScrapeURL: "http://10.0.0.2:9100/metrics",
		model.MetadataLastError: "connection refused",
	}
	target.Status = model.ResourceStatusBroken

	return Snapshot{
		Resources: []model.Resource{apiMetric, cpuMetric, unusedMetric, dashboard, panel, datasource, target},
		Relationships: []model.Relationship{
			relationship(panel.ID, dashboard.ID, model.RelationshipBelongsTo, now),
			relationship(panel.ID, datasource.ID, model.RelationshipUses, now),
			relationship(panel.ID, apiMetric.ID, model.RelationshipUses, now),
		},
	}, nil
}

func resource(resourceType model.ResourceType, name, system, instance, externalID string, now time.Time) model.Resource {
	uid := model.StableID(string(resourceType), system, instance, externalID)
	return model.Resource{
		ID:        uid,
		Type:      resourceType,
		Name:      name,
		UID:       uid,
		Source:    model.SourceInfo{System: system, Instance: instance, ExternalID: externalID},
		Labels:    map[string]string{"environment": "local", model.MetadataOwner: "platform"},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func relationship(fromID, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	id := model.StableID(fromID, string(relationshipType), toID)
	return model.Relationship{
		ID:        id,
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}
