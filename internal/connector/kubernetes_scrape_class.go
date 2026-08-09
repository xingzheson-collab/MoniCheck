package connector

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func kubernetesScrapeClassReference(spec *yaml.Node) string {
	for _, key := range []string{"scrapeClass", "scrapeClassName"} {
		node := yamlMappingValue(spec, key)
		if node != nil && node.Kind == yaml.ScalarNode {
			if value := strings.TrimSpace(node.Value); value != "" {
				return value
			}
		}
	}
	return ""
}

func parseKubernetesScrapeClasses(node *yaml.Node) []kubernetesScrapeClass {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	byName := map[string]kubernetesScrapeClass{}
	order := make([]string, 0)
	for _, definition := range node.Content {
		name := yamlScalarValue(yamlMappingValue(definition, "name"))
		current, exists := byName[name]
		if !exists {
			current.Name = name
			order = append(order, name)
		}
		current.DefinitionCount++
		if yamlBoolValue(yamlMappingValue(definition, "default")) {
			current.Default = true
			current.DefaultDefinitionCount++
		}
		current.OptionCount += yamlMappingOptionCount(definition, "name", "default")
		tlsConfig := yamlMappingValue(definition, "tlsConfig")
		current.TLSConfigDeclared = current.TLSConfigDeclared || yamlValueDeclared(tlsConfig)
		current.TLSInsecureSkipVerify = current.TLSInsecureSkipVerify || yamlBoolValue(yamlMappingValue(tlsConfig, "insecureSkipVerify"))
		current.AuthorizationDeclared = current.AuthorizationDeclared || yamlValueDeclared(yamlMappingValue(definition, "authorization"))
		current.BasicAuthDeclared = current.BasicAuthDeclared || yamlValueDeclared(yamlMappingValue(definition, "basicAuth"))
		current.OAuth2Declared = current.OAuth2Declared || yamlValueDeclared(yamlMappingValue(definition, "oauth2"))
		current.RelabelingCount += yamlSequenceLength(yamlMappingValue(definition, "relabelings"))
		current.MetricRelabelingCount += yamlSequenceLength(yamlMappingValue(definition, "metricRelabelings"))
		byName[name] = current
	}
	result := make([]kubernetesScrapeClass, 0, len(order))
	for _, name := range order {
		result = append(result, byName[name])
	}
	return result
}

func yamlScalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func yamlBoolValue(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	value, err := strconv.ParseBool(strings.TrimSpace(node.Value))
	return err == nil && value
}

func yamlMappingOptionCount(node *yaml.Node, excluded ...string) int {
	if node == nil || node.Kind != yaml.MappingNode {
		return 0
	}
	exclusions := map[string]bool{}
	for _, key := range excluded {
		exclusions[key] = true
	}
	count := 0
	for index := 0; index+1 < len(node.Content); index += 2 {
		if !exclusions[node.Content[index].Value] && node.Content[index+1].Tag != "!!null" {
			count++
		}
	}
	return count
}

func addKubernetesScrapeClassResources(resources map[string]model.Resource, relationships map[string]model.Relationship, workload model.Resource, object kubernetesObject, instance string, now time.Time) {
	defaultCount := 0
	unnamedCount := 0
	duplicateNameCount := 0
	definitionCount := 0
	for _, class := range object.ScrapeClasses {
		definitionCount += class.DefinitionCount
		defaultCount += class.DefaultDefinitionCount
		if class.Name == "" {
			unnamedCount += class.DefinitionCount
			continue
		}
		if class.DefinitionCount > 1 {
			duplicateNameCount++
		}
		resource := newKubernetesScrapeClassResource(workload, class, instance, now)
		resources[resource.ID] = resource
		relationship := kubernetesRelationship(workload.ID, resource.ID, model.RelationshipReferences, now)
		relationship.Metadata = map[string]string{"selection_kind": "ScrapeClass"}
		relationships[relationship.ID] = relationship
	}
	updated := resources[workload.ID]
	updated.Metadata["scrape_class_count"] = strconv.Itoa(definitionCount)
	updated.Metadata["scrape_class_default_count"] = strconv.Itoa(defaultCount)
	updated.Metadata["scrape_class_unnamed_count"] = strconv.Itoa(unnamedCount)
	updated.Metadata["scrape_class_duplicate_name_count"] = strconv.Itoa(duplicateNameCount)
	resources[workload.ID] = updated
}

func newKubernetesScrapeClassResource(workload model.Resource, class kubernetesScrapeClass, instance string, now time.Time) model.Resource {
	externalID := workload.Source.ExternalID + ":scrape-class:" + class.Name
	id := model.StableID(kubernetesSystem, externalID)
	return model.Resource{ID: id, UID: id, Type: model.ResourceTypeScrapeClass, Name: class.Name, Source: model.SourceInfo{System: kubernetesSystem, Instance: instance, ExternalID: externalID}, Metadata: map[string]string{
		"kubernetes_kind":                      "ScrapeClass",
		"namespace":                            workload.Metadata["namespace"],
		"scrape_class_name":                    class.Name,
		"scrape_class_parent_id":               workload.ID,
		"scrape_class_parent_name":             workload.Name,
		"scrape_class_parent_kind":             workload.Metadata["kubernetes_kind"],
		"scrape_class_default":                 strconv.FormatBool(class.Default),
		"scrape_class_definition_count":        strconv.Itoa(class.DefinitionCount),
		"scrape_class_option_count":            strconv.Itoa(class.OptionCount),
		"scrape_class_tls_config_declared":     strconv.FormatBool(class.TLSConfigDeclared),
		"scrape_class_tls_insecure":            strconv.FormatBool(class.TLSInsecureSkipVerify),
		"scrape_class_authorization_declared":  strconv.FormatBool(class.AuthorizationDeclared),
		"scrape_class_basic_auth_declared":     strconv.FormatBool(class.BasicAuthDeclared),
		"scrape_class_oauth2_declared":         strconv.FormatBool(class.OAuth2Declared),
		"scrape_class_relabeling_count":        strconv.Itoa(class.RelabelingCount),
		"scrape_class_metric_relabeling_count": strconv.Itoa(class.MetricRelabelingCount),
		"scrape_class_usage_count":             "0",
	}, Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now}
}

func addKubernetesScrapeClassTopology(resources map[string]model.Resource, relationships map[string]model.Relationship, workloads []kubernetesPrometheusResource, now time.Time) {
	classesByWorkload := map[string]map[string]model.Resource{}
	defaultsByWorkload := map[string][]model.Resource{}
	usage := map[string]int{}
	for _, resource := range resources {
		if resource.Type != model.ResourceTypeScrapeClass || resource.Source.System != kubernetesSystem {
			continue
		}
		parentID := resource.Metadata["scrape_class_parent_id"]
		if classesByWorkload[parentID] == nil {
			classesByWorkload[parentID] = map[string]model.Resource{}
		}
		classesByWorkload[parentID][resource.Metadata["scrape_class_name"]] = resource
		if resource.Metadata["scrape_class_default"] == "true" {
			defaultsByWorkload[parentID] = append(defaultsByWorkload[parentID], resource)
		}
	}
	for resourceID, candidate := range resources {
		kind := strings.TrimSpace(candidate.Metadata["kubernetes_kind"])
		if candidate.Type != model.ResourceTypeTarget || !isKubernetesScrapeClassConsumerKind(kind) {
			continue
		}
		requested := strings.TrimSpace(candidate.Metadata["scrape_class"])
		selectedWorkloads := 0
		missingCount := 0
		appliedCount := 0
		for _, workload := range workloads {
			selectionRelationship := kubernetesRelationship(workload.Resource.ID, candidate.ID, model.RelationshipReferences, now)
			if _, selected := relationships[selectionRelationship.ID]; !selected {
				continue
			}
			selectedWorkloads++
			classes := make([]model.Resource, 0, 1)
			if requested != "" {
				if class, found := classesByWorkload[workload.Resource.ID][requested]; found {
					classes = append(classes, class)
				} else {
					missingCount++
				}
			} else {
				classes = append(classes, defaultsByWorkload[workload.Resource.ID]...)
			}
			for _, class := range classes {
				relationship := kubernetesRelationship(candidate.ID, class.ID, model.RelationshipUses, now)
				relationship.Metadata = map[string]string{"scrape_class_parent_id": workload.Resource.ID, "scrape_class_default": strconv.FormatBool(requested == "")}
				relationships[relationship.ID] = relationship
				usage[class.ID]++
				appliedCount++
			}
		}
		candidate.Metadata["scrape_class_resolution_evaluable"] = strconv.FormatBool(selectedWorkloads > 0)
		candidate.Metadata["scrape_class_selected_workload_count"] = strconv.Itoa(selectedWorkloads)
		candidate.Metadata["scrape_class_missing_workload_count"] = strconv.Itoa(missingCount)
		candidate.Metadata["scrape_class_applied_count"] = strconv.Itoa(appliedCount)
		resources[resourceID] = candidate
	}
	classIDs := make([]string, 0, len(usage))
	for resourceID, resource := range resources {
		if resource.Type == model.ResourceTypeScrapeClass {
			classIDs = append(classIDs, resourceID)
		}
	}
	sort.Strings(classIDs)
	for _, resourceID := range classIDs {
		resource := resources[resourceID]
		resource.Metadata["scrape_class_usage_count"] = strconv.Itoa(usage[resourceID])
		resources[resourceID] = resource
	}
}

func isKubernetesScrapeClassConsumerKind(kind string) bool {
	switch kind {
	case "ServiceMonitor", "PodMonitor", "Probe", "ScrapeConfig":
		return true
	default:
		return false
	}
}
