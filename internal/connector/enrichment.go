package connector

import (
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

var serviceIdentityKeys = []string{
	model.MetadataService,
	"service_name",
	"service.name",
	"app",
	"application",
	"component",
	"app.kubernetes.io/name",
	"k8s_app",
}

var ignoredServiceNames = map[string]bool{
	"unknown": true,
	"none":    true,
	"null":    true,
	"n/a":     true,
	"na":      true,
}

var prometheusCompatibleSystems = map[string]bool{
	"prometheus":      true,
	"thanos":          true,
	"victoriametrics": true,
	"mimir":           true,
	"cortex":          true,
}

var ignoredPrometheusJobServices = map[string]bool{
	"alertmanager":       true,
	"blackbox":           true,
	"blackbox-exporter":  true,
	"cadvisor":           true,
	"grafana":            true,
	"kube-state-metrics": true,
	"loki":               true,
	"node-exporter":      true,
	"otel-collector":     true,
	"prometheus":         true,
	"pushgateway":        true,
	"pyroscope":          true,
	"tempo":              true,
}

const (
	serviceIdentityDeclared = "DECLARED"
	serviceIdentityInferred = "INFERRED"
)

var serviceOwnershipKeys = []string{
	model.MetadataOwner,
	"team",
	"squad",
	"maintainer",
	"responsible",
}

func EnrichBusinessServices(snapshot Snapshot, now time.Time) Snapshot {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	resourcesByID := make(map[string]model.Resource, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		resourcesByID[resource.ID] = resource
	}
	relationshipsByID := make(map[string]model.Relationship, len(snapshot.Relationships))
	for _, relationship := range snapshot.Relationships {
		relationshipsByID[relationship.ID] = relationship
	}

	for _, resource := range snapshot.Resources {
		if !isServiceConsumerResource(resource) {
			continue
		}
		serviceName, sourceKey, confidence, ok := resourceServiceIdentity(resource)
		if !ok {
			continue
		}
		serviceResource := businessServiceResource(serviceName, now)
		if existing, ok := resourcesByID[serviceResource.ID]; ok {
			serviceResource = existing
		}
		mergeServiceIdentity(&serviceResource, sourceKey, confidence)
		mergeServiceOwnership(&serviceResource, resource)
		resourcesByID[serviceResource.ID] = serviceResource
		relationship := model.Relationship{
			ID:     model.StableID(resource.ID, string(model.RelationshipBelongsTo), serviceResource.ID),
			FromID: resource.ID,
			ToID:   serviceResource.ID,
			Type:   model.RelationshipBelongsTo,
			Metadata: map[string]string{
				"derived_from":        sourceKey,
				"identity_confidence": confidence,
			},
			CreatedAt: now,
		}
		relationshipsByID[relationship.ID] = relationship
	}

	enriched := Snapshot{
		Resources:     make([]model.Resource, 0, len(resourcesByID)),
		References:    append([]model.Resource(nil), snapshot.References...),
		Relationships: make([]model.Relationship, 0, len(relationshipsByID)),
		Diagnostics:   append([]model.Diagnostic(nil), snapshot.Diagnostics...),
		Partial:       snapshot.Partial,
	}
	for _, resource := range resourcesByID {
		enriched.Resources = append(enriched.Resources, resource)
	}
	for _, relationship := range relationshipsByID {
		enriched.Relationships = append(enriched.Relationships, relationship)
	}
	sort.Slice(enriched.Resources, func(i, j int) bool {
		return enriched.Resources[i].ID < enriched.Resources[j].ID
	})
	sort.Slice(enriched.Relationships, func(i, j int) bool {
		return enriched.Relationships[i].ID < enriched.Relationships[j].ID
	})
	return enriched
}

func mergeServiceOwnership(service *model.Resource, resource model.Resource) {
	if service.Labels == nil {
		service.Labels = map[string]string{}
	}
	if service.Metadata == nil {
		service.Metadata = map[string]string{}
	}
	for _, key := range serviceOwnershipKeys {
		if service.Labels[key] != "" || service.Metadata[key] != "" {
			continue
		}
		value := strings.TrimSpace(resource.Labels[key])
		if value == "" {
			value = strings.TrimSpace(resource.Metadata[key])
		}
		if value == "" {
			continue
		}
		service.Labels[key] = value
		service.Metadata[key] = value
	}
}

func isServiceConsumerResource(resource model.Resource) bool {
	if resource.Status != "" && resource.Status != model.ResourceStatusActive && resource.Status != model.ResourceStatusBroken {
		return false
	}
	switch resource.Type {
	case model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
		model.ResourceTypeDatasource,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeExporter,
		model.ResourceTypeTraceService,
		model.ResourceTypeProfileService:
		return true
	default:
		return false
	}
}

func resourceServiceIdentity(resource model.Resource) (string, string, string, bool) {
	for _, key := range serviceIdentityKeys {
		if value, ok := cleanServiceName(resource.Labels[key]); ok {
			return value, "label." + key, serviceIdentityDeclared, true
		}
	}
	for _, key := range serviceIdentityKeys {
		if value, ok := cleanServiceName(resource.Metadata[key]); ok {
			return value, "metadata." + key, serviceIdentityDeclared, true
		}
	}
	if value, ok := inferredPrometheusJobService(resource); ok {
		return value, resource.Source.System + ".job", serviceIdentityInferred, true
	}
	return "", "", "", false
}

func inferredPrometheusJobService(resource model.Resource) (string, bool) {
	if resource.Type != model.ResourceTypeJob || !prometheusCompatibleSystems[strings.ToLower(strings.TrimSpace(resource.Source.System))] {
		return "", false
	}
	value, ok := cleanServiceName(resource.Name)
	if !ok {
		return "", false
	}
	normalized := strings.ToLower(value)
	if ignoredPrometheusJobServices[normalized] || strings.HasSuffix(normalized, "-exporter") || strings.HasSuffix(normalized, "_exporter") || strings.HasPrefix(normalized, "kube-") || strings.HasPrefix(normalized, "kubernetes-") {
		return "", false
	}
	return value, true
}

func mergeServiceIdentity(service *model.Resource, source string, confidence string) {
	if service.Metadata == nil {
		service.Metadata = map[string]string{}
	}
	currentConfidence := service.Metadata[model.MetadataServiceIdentityConfidence]
	currentSource := service.Metadata[model.MetadataServiceIdentitySource]
	if currentConfidence == serviceIdentityDeclared && confidence != serviceIdentityDeclared {
		return
	}
	if currentConfidence == confidence && currentSource != "" && currentSource <= source {
		return
	}
	service.Metadata[model.MetadataServiceIdentitySource] = source
	service.Metadata[model.MetadataServiceIdentityConfidence] = confidence
}

func cleanServiceName(value string) (string, bool) {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	normalized := strings.ToLower(value)
	if ignoredServiceNames[normalized] {
		return "", false
	}
	return value, true
}

func businessServiceResource(name string, now time.Time) model.Resource {
	uid := model.StableID(string(model.ResourceTypeService), "monicheck", "global", "service:"+strings.ToLower(name))
	return model.Resource{
		ID:   uid,
		Type: model.ResourceTypeService,
		Name: name,
		UID:  uid,
		Source: model.SourceInfo{
			System:     "monicheck",
			Instance:   "global",
			ExternalID: "service:" + strings.ToLower(name),
		},
		Labels: map[string]string{
			model.MetadataService: name,
		},
		Metadata: map[string]string{
			model.MetadataService: name,
			"derived":             "true",
		},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}
