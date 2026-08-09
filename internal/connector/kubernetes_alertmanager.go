package connector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerObject(object *kubernetesObject, definition kubernetesManifestObjectDefinition, node *yaml.Node) {
	object.AlertmanagerVersion = strings.TrimSpace(definition.Spec.Version)
	object.AlertmanagerPaused = definition.Spec.Paused
	object.AlertmanagerReplicas = 1
	if definition.Spec.Replicas != nil {
		object.AlertmanagerReplicas = *definition.Spec.Replicas
		object.AlertmanagerReplicasDeclared = true
	}
	spec := yamlMappingValue(node, "spec")
	populateKubernetesAlertmanagerStorageObject(object, spec)
	populateKubernetesAlertmanagerLimitsObject(object, spec)
	populateKubernetesAlertmanagerSecurityObject(object, spec)
	populateKubernetesAlertmanagerArgumentsObject(object, spec)
	populateKubernetesAlertmanagerWebObject(object, spec)
	populateKubernetesAlertmanagerClusterObject(object, spec)
	populateKubernetesAlertmanagerRolloutObject(object, spec)
	populateKubernetesAlertmanagerRuntimeObject(object, spec)
	populateKubernetesAlertmanagerConfigSourceObject(object, spec)
	populateKubernetesAlertmanagerPodSecurityObject(object, spec)
	populateKubernetesAlertmanagerResourceObject(object, spec)
	populateKubernetesAlertmanagerStatefulSetObject(object, spec)
	populateKubernetesAlertmanagerDNSObject(object, spec)
	populateKubernetesAlertmanagerImageObject(object, spec)
	populateKubernetesAlertmanagerVolumeObject(object, spec)
	populateKubernetesAlertmanagerPlacementObject(object, spec)
	populateKubernetesAlertmanagerPodReferenceObject(object, spec)
	populateKubernetesAlertmanagerPodCustomizationObject(object, spec)
	object.PrometheusSelections = map[string]kubernetesPrometheusSelection{
		"AlertmanagerConfig": {
			ResourceSelector:  parseKubernetesLabelSelector(yamlMappingValue(spec, "alertmanagerConfigSelector")),
			NamespaceSelector: parseKubernetesLabelSelector(yamlMappingValue(spec, "alertmanagerConfigNamespaceSelector")),
		},
	}
}

func populateKubernetesAlertmanagerConfigObject(object *kubernetesObject, node *yaml.Node) {
	spec := yamlMappingValue(node, "spec")
	if spec == nil {
		return
	}
	var decoded map[string]any
	if err := spec.Decode(&decoded); err != nil {
		return
	}
	normalized := normalizeAlertmanagerConfigValue(decoded, "")
	encoded, err := yaml.Marshal(normalized)
	if err == nil {
		object.AlertmanagerConfigYAML = string(encoded)
	}
}

func normalizeAlertmanagerConfigValue(value any, parentKey string) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			normalizedKey := camelToSnake(key)
			if (normalizedKey == "source_match" || normalizedKey == "target_match") && alertmanagerConfigSequence(child) {
				normalizedKey += "ers"
			}
			if normalizedKey == "matchers" || normalizedKey == "source_matchers" || normalizedKey == "target_matchers" {
				result[normalizedKey] = normalizeAlertmanagerConfigMatchers(child)
				continue
			}
			result[normalizedKey] = normalizeAlertmanagerConfigValue(child, normalizedKey)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			keyString := strings.TrimSpace(fmt.Sprint(key))
			if keyString != "" {
				result[camelToSnake(keyString)] = normalizeAlertmanagerConfigValue(child, parentKey)
			}
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			result = append(result, normalizeAlertmanagerConfigValue(child, parentKey))
		}
		return result
	default:
		return value
	}
}

func alertmanagerConfigSequence(value any) bool {
	_, ok := value.([]any)
	return ok
}

func normalizeAlertmanagerConfigMatchers(value any) any {
	items, ok := value.([]any)
	if !ok {
		return normalizeAlertmanagerConfigValue(value, "matchers")
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			if text = strings.TrimSpace(text); text != "" {
				result = append(result, text)
			}
			continue
		}
		matcher := kubernetesStringAnyMap(item)
		name := strings.TrimSpace(fmt.Sprint(matcher["name"]))
		value := strings.TrimSpace(fmt.Sprint(matcher["value"]))
		operator := strings.TrimSpace(fmt.Sprint(matcher["matchType"]))
		if operator == "" || operator == "<nil>" {
			operator = "="
			if regex, ok := matcher["regex"].(bool); ok && regex {
				operator = "=~"
			}
		}
		if name != "" && name != "<nil>" && value != "<nil>" {
			result = append(result, name+operator+strconv.Quote(value))
		}
	}
	return result
}

func kubernetesStringAnyMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[fmt.Sprint(key)] = child
		}
		return result
	default:
		return map[string]any{}
	}
}

func camelToSnake(value string) string {
	var result strings.Builder
	for index, character := range value {
		if unicode.IsUpper(character) {
			if index > 0 {
				result.WriteByte('_')
			}
			result.WriteRune(unicode.ToLower(character))
			continue
		}
		result.WriteRune(character)
	}
	return result.String()
}

func addKubernetesAlertmanagerConfigResources(resources map[string]model.Resource, relationships map[string]model.Relationship, object kubernetesObject, instance string, now time.Time) model.Resource {
	configName := kubernetesObjectName(object)
	policy := newKubernetesAlertmanagerConfigResource(model.ResourceTypeNotificationPolicy, configName, "policy", instance, object, now)
	policy.Labels = cloneLabels(object.Labels)
	policy.Metadata["alertmanager_config_route_declared"] = "false"
	if stats, ok := alertmanagerRoutingPolicyStats(object.AlertmanagerConfigYAML); ok {
		applyRoutingPolicyMetadata(&policy, stats)
		policy.Metadata["alertmanager_config_route_declared"] = "true"
	}
	resources[policy.ID] = policy

	declared, routed, integrations := alertmanagerConfigReceivers(object.AlertmanagerConfigYAML)
	insecureCounts := alertmanagerReceiverInsecureEndpointCounts(object.AlertmanagerConfigYAML)
	receiverNames := make(map[string]bool)
	for name := range declared {
		receiverNames[name] = true
	}
	for name := range routed {
		receiverNames[name] = true
	}
	orderedReceivers := make([]string, 0, len(receiverNames))
	for name := range receiverNames {
		orderedReceivers = append(orderedReceivers, name)
	}
	sort.Strings(orderedReceivers)
	for _, name := range orderedReceivers {
		receiver := newKubernetesAlertmanagerConfigResource(model.ResourceTypeReceiver, name, "receiver:"+name, instance, object, now)
		receiver.Metadata["declared"] = strconv.FormatBool(declared[name])
		receiver.Metadata["referenced_by_route"] = strconv.FormatBool(routed[name])
		receiver.Metadata[model.MetadataReceiverIntegrations] = strings.Join(integrations[name], ",")
		receiver.Metadata[model.MetadataReceiverInsecureEndpointCount] = strconv.Itoa(insecureCounts[name])
		resources[receiver.ID] = receiver
		if routed[name] {
			relationship := kubernetesRelationship(policy.ID, receiver.ID, model.RelationshipUses, now)
			relationships[relationship.ID] = relationship
		}
	}

	for _, interval := range alertmanagerTimeIntervals(object.AlertmanagerConfigYAML) {
		resource := newKubernetesAlertmanagerConfigResource(model.ResourceTypeTimeInterval, interval.name, "time-interval:"+interval.name, instance, object, now)
		resource.Metadata[model.MetadataTimeIntervalDeclared] = strconv.FormatBool(interval.declared)
		resource.Metadata[model.MetadataTimeIntervalSpecCount] = strconv.Itoa(interval.specCount)
		resource.Metadata[model.MetadataTimeIntervalMuteRefCount] = strconv.Itoa(interval.muteRefCount)
		resource.Metadata[model.MetadataTimeIntervalActiveRefCount] = strconv.Itoa(interval.activeRefCount)
		resources[resource.ID] = resource
		if interval.muteRefCount+interval.activeRefCount > 0 {
			relationship := kubernetesRelationship(policy.ID, resource.ID, model.RelationshipUses, now)
			relationships[relationship.ID] = relationship
		}
	}
	for _, inhibition := range alertmanagerInhibitionRules(object.AlertmanagerConfigYAML) {
		resource := newKubernetesAlertmanagerConfigResource(model.ResourceTypeInhibitionRule, inhibition.name, inhibition.externalID, instance, object, now)
		applyInhibitionRuleMetadata(&resource, inhibition)
		resources[resource.ID] = resource
	}
	return policy
}

func newKubernetesAlertmanagerConfigResource(resourceType model.ResourceType, name, suffix, instance string, object kubernetesObject, now time.Time) model.Resource {
	externalID := "alertmanagerconfig:" + kubernetesObjectName(object) + ":" + suffix
	id := model.StableID(kubernetesSystem, externalID)
	return model.Resource{ID: id, UID: id, Type: resourceType, Name: name, Source: model.SourceInfo{System: kubernetesSystem, Instance: instance, ExternalID: externalID}, Metadata: map[string]string{"kubernetes_kind": "AlertmanagerConfig", "namespace": object.Namespace, "alertmanager_config": kubernetesObjectName(object)}, Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now}
}

func addKubernetesAlertmanagerSelections(resources map[string]model.Resource, relationships map[string]model.Relationship, alertmanagers []kubernetesPrometheusResource, configs []kubernetesAlertmanagerConfigResource, namespaceLabels, objectLabels map[string]map[string]string, now time.Time) {
	selectedByAlertmanager := map[string]int{}
	directConfigFound := map[string]bool{}
	for _, config := range configs {
		candidate := resources[config.Resource.ID]
		labels := objectLabels[kubernetesSelectionObjectKey("AlertmanagerConfig", kubernetesObjectName(config.Object))]
		allKnown := true
		selectedCount := 0
		nonzeroCount := 0
		for _, alertmanager := range alertmanagers {
			directSelected := alertmanager.Object.Namespace == config.Object.Namespace && alertmanager.Object.AlertmanagerConfigurationName != "" && alertmanager.Object.AlertmanagerConfigurationName == config.Object.Name
			selected := directSelected
			if directSelected {
				directConfigFound[alertmanager.Resource.ID] = true
			}
			if !selected {
				selection := alertmanager.Object.PrometheusSelections["AlertmanagerConfig"]
				resourceMatches, resourceKnown := kubernetesLabelSelectorMatches(selection.ResourceSelector, labels)
				if !resourceKnown {
					allKnown = false
					continue
				}
				if !resourceMatches {
					continue
				}
				namespaceMatches, namespaceKnown := kubernetesNamespaceSelectorMatches(selection.NamespaceSelector, alertmanager.Object.Namespace, config.Object.Namespace, namespaceLabels)
				if !namespaceKnown {
					allKnown = false
					continue
				}
				selected = namespaceMatches
			}
			if !selected {
				continue
			}
			relationship := kubernetesRelationship(alertmanager.Resource.ID, candidate.ID, model.RelationshipReferences, now)
			relationship.Metadata = map[string]string{"selection_kind": "AlertmanagerConfig"}
			relationships[relationship.ID] = relationship
			selectedCount++
			selectedByAlertmanager[alertmanager.Resource.ID]++
			if alertmanager.Object.AlertmanagerReplicas > 0 {
				nonzeroCount++
			}
		}
		candidate.Metadata["alertmanager_selection_candidate"] = "true"
		candidate.Metadata["alertmanager_selection_evaluable"] = strconv.FormatBool(selectedCount > 0 || allKnown)
		candidate.Metadata["alertmanager_selected_count"] = strconv.Itoa(selectedCount)
		candidate.Metadata["alertmanager_nonzero_selected_count"] = strconv.Itoa(nonzeroCount)
		resources[candidate.ID] = candidate
	}
	serviceUsers := map[string]int{}
	for _, alertmanager := range alertmanagers {
		serviceName := alertmanager.Object.AlertmanagerServiceName
		if serviceName == "" {
			serviceName = "alertmanager-operated"
		}
		serviceUsers[alertmanager.Object.Namespace+"\x00"+serviceName]++
	}
	for _, alertmanager := range alertmanagers {
		resource := resources[alertmanager.Resource.ID]
		resource.Metadata["alertmanager_selected_config_count"] = strconv.Itoa(selectedByAlertmanager[alertmanager.Resource.ID])
		resource.Metadata["alertmanager_configuration_found"] = strconv.FormatBool(directConfigFound[alertmanager.Resource.ID])
		serviceName := alertmanager.Object.AlertmanagerServiceName
		if serviceName == "" {
			serviceName = "alertmanager-operated"
		}
		sharedCount := serviceUsers[alertmanager.Object.Namespace+"\x00"+serviceName] - 1
		resource.Metadata["alertmanager_shared_service_count"] = strconv.Itoa(sharedCount)
		resources[resource.ID] = resource
	}
}
