package connector

import (
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestEnrichBusinessServices(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	metric := testResource("metric-api", model.ResourceTypeMetric, "http_requests_total", map[string]string{"service": "api", model.MetadataOwner: "payments"}, nil)
	alertRule := testResource("alert-api", model.ResourceTypeAlertRule, "APIHighErrorRate", map[string]string{"app": "api", "team": "platform"}, nil)
	dashboard := testResource("dashboard-checkout", model.ResourceTypeDashboard, "Checkout", nil, map[string]string{"application": "checkout"})
	traceService := testResource("trace-service-orders", model.ResourceTypeTraceService, "orders", map[string]string{model.MetadataService: "orders"}, nil)
	unknown := testResource("metric-unknown", model.ResourceTypeMetric, "unknown_metric", map[string]string{"service": "unknown"}, nil)
	service := businessServiceResource("api", now)
	existing := model.Relationship{
		ID:        model.StableID(metric.ID, string(model.RelationshipBelongsTo), service.ID),
		FromID:    metric.ID,
		ToID:      service.ID,
		Type:      model.RelationshipBelongsTo,
		CreatedAt: now,
	}

	snapshot := EnrichBusinessServices(Snapshot{
		Resources:     []model.Resource{metric, alertRule, dashboard, traceService, unknown},
		Relationships: []model.Relationship{existing},
	}, now)

	assertServiceResource(t, snapshot, "api")
	assertServiceOwnership(t, snapshot, "api", "payments", "platform")
	assertServiceResource(t, snapshot, "checkout")
	assertServiceResource(t, snapshot, "orders")
	assertNoServiceResource(t, snapshot, "unknown")
	assertServiceRelationship(t, snapshot, metric.ID, "api", "label.service")
	assertServiceRelationship(t, snapshot, alertRule.ID, "api", "label.app")
	assertServiceRelationship(t, snapshot, dashboard.ID, "checkout", "metadata.application")
	assertServiceRelationship(t, snapshot, traceService.ID, "orders", "label.service")
	assertResourceCount(t, snapshot, model.ResourceTypeService, 3)
}

func TestEnrichBusinessServicesInfersPrometheusJobWithExplicitProvenance(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	checkout := testResource("job-checkout", model.ResourceTypeJob, "checkout", nil, nil)
	checkout.Source.System = prometheusSystem
	nodeExporter := testResource("job-node", model.ResourceTypeJob, "node-exporter", nil, nil)
	nodeExporter.Source.System = prometheusSystem
	explicit := testResource("metric-checkout", model.ResourceTypeMetric, "requests_total", map[string]string{model.MetadataService: "checkout"}, nil)
	explicit.Source.System = prometheusSystem

	snapshot := EnrichBusinessServices(Snapshot{Resources: []model.Resource{checkout, nodeExporter, explicit}}, now)
	assertNoServiceResource(t, snapshot, "node-exporter")
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Name == "checkout" {
			if resource.Metadata[model.MetadataServiceIdentityConfidence] != serviceIdentityDeclared || resource.Metadata[model.MetadataServiceIdentitySource] != "label.service" {
				t.Fatalf("explicit service identity must outrank job inference: %#v", resource.Metadata)
			}
			assertServiceRelationship(t, snapshot, checkout.ID, "checkout", "prometheus.job")
			return
		}
	}
	t.Fatal("expected checkout service")
}

func TestEnrichBusinessServicesInfersJobWhenNoServiceLabelExists(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	job := testResource("job-payments", model.ResourceTypeJob, "payments", nil, nil)
	job.Source.System = prometheusSystem
	snapshot := EnrichBusinessServices(Snapshot{Resources: []model.Resource{job}}, now)
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Name == "payments" {
			if resource.Metadata[model.MetadataServiceIdentityConfidence] != serviceIdentityInferred || resource.Metadata[model.MetadataServiceIdentitySource] != "prometheus.job" {
				t.Fatalf("unexpected inferred identity: %#v", resource.Metadata)
			}
			return
		}
	}
	t.Fatal("expected inferred payments service")
}

func assertServiceOwnership(t *testing.T, snapshot Snapshot, name string, owner string, team string) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Name == name {
			if resource.Labels[model.MetadataOwner] != owner || resource.Metadata[model.MetadataOwner] != owner {
				t.Fatalf("expected service owner %q, got labels=%#v metadata=%#v", owner, resource.Labels, resource.Metadata)
			}
			if resource.Labels["team"] != team || resource.Metadata["team"] != team {
				t.Fatalf("expected service team %q, got labels=%#v metadata=%#v", team, resource.Labels, resource.Metadata)
			}
			return
		}
	}
	t.Fatalf("expected service resource %q", name)
}

func testResource(id string, resourceType model.ResourceType, name string, labels map[string]string, metadata map[string]string) model.Resource {
	return model.Resource{
		ID:       id,
		Type:     resourceType,
		Name:     name,
		UID:      id,
		Source:   model.SourceInfo{System: "test", Instance: "local", ExternalID: id},
		Labels:   labels,
		Metadata: metadata,
		Status:   model.ResourceStatusActive,
	}
}

func assertServiceResource(t *testing.T, snapshot Snapshot, name string) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Name == name {
			if resource.Source.System != "monicheck" || resource.Metadata[model.MetadataService] != name {
				t.Fatalf("expected derived service metadata, got %#v", resource)
			}
			return
		}
	}
	t.Fatalf("expected service resource %q", name)
}

func assertNoServiceResource(t *testing.T, snapshot Snapshot, name string) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Type == model.ResourceTypeService && resource.Name == name {
			t.Fatalf("did not expect service resource %q", name)
		}
	}
}

func assertServiceRelationship(t *testing.T, snapshot Snapshot, fromID string, serviceName string, derivedFrom string) {
	t.Helper()
	serviceID := businessServiceResource(serviceName, time.Unix(0, 0).UTC()).ID
	for _, relationship := range snapshot.Relationships {
		if relationship.FromID == fromID && relationship.ToID == serviceID && relationship.Type == model.RelationshipBelongsTo {
			if relationship.Metadata["derived_from"] != derivedFrom {
				t.Fatalf("expected derived_from %q, got %#v", derivedFrom, relationship.Metadata)
			}
			return
		}
	}
	t.Fatalf("expected service relationship from %q to %q", fromID, serviceName)
}
