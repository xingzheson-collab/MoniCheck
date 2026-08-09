package connector

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func parseKubernetesRemoteWrites(node *yaml.Node) []kubernetesRemoteWrite {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	result := make([]kubernetesRemoteWrite, 0, len(node.Content))
	for index, definition := range node.Content {
		result = append(result, parseKubernetesRemoteWrite(definition, index))
	}
	return result
}

func parseKubernetesRemoteWrite(node *yaml.Node, index int) kubernetesRemoteWrite {
	remoteWrite := kubernetesRemoteWrite{
		Name:           yamlScalarValue(yamlMappingValue(node, "name")),
		Index:          index,
		MessageVersion: yamlScalarValue(yamlMappingValue(node, "messageVersion")),
		SendExemplars:  yamlBoolValue(yamlMappingValue(node, "sendExemplars")),
		SendNativeHistograms: yamlBoolValue(
			yamlMappingValue(node, "sendNativeHistograms"),
		),
	}
	endpoint := yamlScalarValue(yamlMappingValue(node, "url"))
	remoteWrite.DestinationDeclared = endpoint != ""
	remoteWrite.URLScheme, remoteWrite.URLValid = safeRemoteWriteURLMetadata(endpoint)
	remoteWrite.TLSConfigDeclared = yamlValueDeclared(yamlMappingValue(node, "tlsConfig"))
	remoteWrite.TLSInsecureSkipVerify = yamlBoolValue(yamlMappingValue(yamlMappingValue(node, "tlsConfig"), "insecureSkipVerify"))
	remoteWrite.AuthorizationDeclared = yamlValueDeclared(yamlMappingValue(node, "authorization"))
	remoteWrite.BasicAuthDeclared = yamlValueDeclared(yamlMappingValue(node, "basicAuth"))
	remoteWrite.OAuth2Declared = yamlValueDeclared(yamlMappingValue(node, "oauth2"))
	remoteWrite.SigV4Declared = yamlValueDeclared(yamlMappingValue(node, "sigv4"))
	remoteWrite.AzureADDeclared = yamlValueDeclared(yamlMappingValue(node, "azureAd"))
	remoteWrite.BearerTokenDeclared = yamlValueDeclared(yamlMappingValue(node, "bearerToken")) || yamlValueDeclared(yamlMappingValue(node, "bearerTokenSecret"))
	remoteWrite.BearerTokenFileDeclared = yamlValueDeclared(yamlMappingValue(node, "bearerTokenFile"))
	for _, declared := range []bool{remoteWrite.AuthorizationDeclared, remoteWrite.BasicAuthDeclared, remoteWrite.OAuth2Declared, remoteWrite.SigV4Declared, remoteWrite.AzureADDeclared, remoteWrite.BearerTokenDeclared, remoteWrite.BearerTokenFileDeclared} {
		if declared {
			remoteWrite.AuthMethodCount++
		}
	}
	remoteWrite.HeaderCount = yamlMappingLength(yamlMappingValue(node, "headers"))
	remoteWrite.WriteRelabelingCount = yamlSequenceLength(yamlMappingValue(node, "writeRelabelConfigs"))
	remoteWrite.ProxyDeclared = yamlValueDeclared(yamlMappingValue(node, "proxyUrl")) || yamlBoolValue(yamlMappingValue(node, "proxyFromEnvironment")) || yamlValueDeclared(yamlMappingValue(node, "proxyConnectHeader"))
	queue := yamlMappingValue(node, "queueConfig")
	remoteWrite.QueueConfigDeclared = yamlValueDeclared(queue)
	remoteWrite.QueueCapacity, remoteWrite.QueueCapacityDeclared, remoteWrite.QueueCapacityValid = yamlIntegerValue(yamlMappingValue(queue, "capacity"))
	remoteWrite.QueueMinShards, remoteWrite.QueueMinShardsDeclared, remoteWrite.QueueMinShardsValid = yamlIntegerValue(yamlMappingValue(queue, "minShards"))
	remoteWrite.QueueMaxShards, remoteWrite.QueueMaxShardsDeclared, remoteWrite.QueueMaxShardsValid = yamlIntegerValue(yamlMappingValue(queue, "maxShards"))
	remoteWrite.QueueMaxSamplesPerSend, remoteWrite.QueueMaxSamplesDeclared, remoteWrite.QueueMaxSamplesValid = yamlIntegerValue(yamlMappingValue(queue, "maxSamplesPerSend"))
	remoteWrite.MetadataConfigDeclared = yamlValueDeclared(yamlMappingValue(node, "metadataConfig"))
	return remoteWrite
}

func populateKubernetesRemoteWriteCRDObject(object *kubernetesObject, node *yaml.Node) {
	spec := yamlMappingValue(node, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return
	}
	object.RemoteWrites = []kubernetesRemoteWrite{parseKubernetesRemoteWrite(spec, 0)}
}

func safeRemoteWriteURLMetadata(endpoint string) (string, bool) {
	if endpoint == "" {
		return "", false
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "other", false
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return "other", false
	}
	return scheme, true
}

func yamlMappingLength(node *yaml.Node) int {
	if node == nil || node.Kind != yaml.MappingNode {
		return 0
	}
	return len(node.Content) / 2
}

func yamlIntegerValue(node *yaml.Node) (int, bool, bool) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return 0, false, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(node.Value))
	return value, true, err == nil
}

func addKubernetesInlineRemoteWriteResources(resources map[string]model.Resource, relationships map[string]model.Relationship, workload model.Resource, object kubernetesObject, instance string, now time.Time) {
	names := map[string]int{}
	for _, remoteWrite := range object.RemoteWrites {
		resource := newKubernetesInlineRemoteWriteResource(workload, remoteWrite, instance, now)
		resources[resource.ID] = resource
		relationship := kubernetesRelationship(workload.ID, resource.ID, model.RelationshipUses, now)
		relationship.Metadata = map[string]string{"usage_kind": "RemoteWrite", "remote_write_origin": "inline"}
		relationships[relationship.ID] = relationship
		if remoteWrite.Name != "" {
			names[remoteWrite.Name]++
		}
	}
	updated := resources[workload.ID]
	updated.Metadata["remote_write_inline_count"] = strconv.Itoa(len(object.RemoteWrites))
	updated.Metadata["remote_write_selected_crd_count"] = "0"
	updated.Metadata["remote_write_effective_count"] = strconv.Itoa(len(object.RemoteWrites))
	updated.Metadata["remote_write_duplicate_name_count"] = strconv.Itoa(duplicateRemoteWriteNameCount(names))
	if object.Kind == "Prometheus" || object.Kind == "PrometheusAgent" {
		updated.Metadata["prometheus_remote_write_count"] = strconv.Itoa(len(object.RemoteWrites))
	}
	if object.Kind == "ThanosRuler" {
		updated.Metadata["thanos_ruler_remote_write_count"] = strconv.Itoa(len(object.RemoteWrites))
	}
	resources[workload.ID] = updated
}

func newKubernetesInlineRemoteWriteResource(workload model.Resource, remoteWrite kubernetesRemoteWrite, instance string, now time.Time) model.Resource {
	externalID := fmt.Sprintf("%s:remote-write:%d", workload.Source.ExternalID, remoteWrite.Index)
	name := remoteWrite.Name
	if name == "" {
		name = fmt.Sprintf("remote-write-%d", remoteWrite.Index+1)
	}
	resource := kubernetesManifestResource(model.ResourceTypeExporter, name, instance, externalID, now)
	populateKubernetesRemoteWriteMetadata(&resource, remoteWrite, "inline")
	resource.Metadata["namespace"] = workload.Metadata["namespace"]
	resource.Metadata["remote_write_parent_id"] = workload.ID
	resource.Metadata["remote_write_parent_name"] = workload.Name
	resource.Metadata["remote_write_parent_kind"] = workload.Metadata["kubernetes_kind"]
	return resource
}

func newKubernetesRemoteWriteCRDResource(object kubernetesObject, instance string, now time.Time) model.Resource {
	resource := kubernetesResource(model.ResourceTypeExporter, kubernetesObjectName(object), instance, object, now)
	remoteWrite := kubernetesRemoteWrite{}
	if len(object.RemoteWrites) > 0 {
		remoteWrite = object.RemoteWrites[0]
	}
	populateKubernetesRemoteWriteMetadata(&resource, remoteWrite, "crd")
	resource.Labels = cloneLabels(object.Labels)
	resource.Metadata["namespace"] = object.Namespace
	resource.Metadata["remote_write_crd_proposal"] = "true"
	resource.Metadata["remote_write_selection_candidate"] = "true"
	resource.Metadata["remote_write_selection_evaluable"] = "false"
	resource.Metadata["remote_write_selected_count"] = "0"
	return resource
}

func populateKubernetesRemoteWriteMetadata(resource *model.Resource, remoteWrite kubernetesRemoteWrite, origin string) {
	resource.Metadata["kubernetes_kind"] = "RemoteWrite"
	resource.Metadata["remote_write_origin"] = origin
	resource.Metadata["remote_write_name"] = remoteWrite.Name
	resource.Metadata["remote_write_name_declared"] = strconv.FormatBool(remoteWrite.Name != "")
	resource.Metadata["remote_write_destination_declared"] = strconv.FormatBool(remoteWrite.DestinationDeclared)
	resource.Metadata["remote_write_url_scheme"] = remoteWrite.URLScheme
	resource.Metadata["remote_write_url_valid"] = strconv.FormatBool(remoteWrite.URLValid)
	resource.Metadata["remote_write_message_version"] = remoteWrite.MessageVersion
	resource.Metadata["remote_write_send_exemplars"] = strconv.FormatBool(remoteWrite.SendExemplars)
	resource.Metadata["remote_write_send_native_histograms"] = strconv.FormatBool(remoteWrite.SendNativeHistograms)
	resource.Metadata["remote_write_tls_config_declared"] = strconv.FormatBool(remoteWrite.TLSConfigDeclared)
	resource.Metadata["remote_write_tls_insecure"] = strconv.FormatBool(remoteWrite.TLSInsecureSkipVerify)
	resource.Metadata["remote_write_authorization_declared"] = strconv.FormatBool(remoteWrite.AuthorizationDeclared)
	resource.Metadata["remote_write_basic_auth_declared"] = strconv.FormatBool(remoteWrite.BasicAuthDeclared)
	resource.Metadata["remote_write_oauth2_declared"] = strconv.FormatBool(remoteWrite.OAuth2Declared)
	resource.Metadata["remote_write_sigv4_declared"] = strconv.FormatBool(remoteWrite.SigV4Declared)
	resource.Metadata["remote_write_azure_ad_declared"] = strconv.FormatBool(remoteWrite.AzureADDeclared)
	resource.Metadata["remote_write_deprecated_bearer_declared"] = strconv.FormatBool(remoteWrite.BearerTokenDeclared || remoteWrite.BearerTokenFileDeclared)
	resource.Metadata["remote_write_auth_method_count"] = strconv.Itoa(remoteWrite.AuthMethodCount)
	resource.Metadata["remote_write_header_count"] = strconv.Itoa(remoteWrite.HeaderCount)
	resource.Metadata["remote_write_relabeling_count"] = strconv.Itoa(remoteWrite.WriteRelabelingCount)
	resource.Metadata["remote_write_proxy_declared"] = strconv.FormatBool(remoteWrite.ProxyDeclared)
	resource.Metadata["remote_write_queue_config_declared"] = strconv.FormatBool(remoteWrite.QueueConfigDeclared)
	resource.Metadata["remote_write_queue_capacity_declared"] = strconv.FormatBool(remoteWrite.QueueCapacityDeclared)
	resource.Metadata["remote_write_queue_capacity_valid"] = strconv.FormatBool(remoteWrite.QueueCapacityValid)
	resource.Metadata["remote_write_queue_capacity"] = strconv.Itoa(remoteWrite.QueueCapacity)
	resource.Metadata["remote_write_queue_min_shards_declared"] = strconv.FormatBool(remoteWrite.QueueMinShardsDeclared)
	resource.Metadata["remote_write_queue_min_shards_valid"] = strconv.FormatBool(remoteWrite.QueueMinShardsValid)
	resource.Metadata["remote_write_queue_min_shards"] = strconv.Itoa(remoteWrite.QueueMinShards)
	resource.Metadata["remote_write_queue_max_shards_declared"] = strconv.FormatBool(remoteWrite.QueueMaxShardsDeclared)
	resource.Metadata["remote_write_queue_max_shards_valid"] = strconv.FormatBool(remoteWrite.QueueMaxShardsValid)
	resource.Metadata["remote_write_queue_max_shards"] = strconv.Itoa(remoteWrite.QueueMaxShards)
	resource.Metadata["remote_write_queue_max_samples_declared"] = strconv.FormatBool(remoteWrite.QueueMaxSamplesDeclared)
	resource.Metadata["remote_write_queue_max_samples_valid"] = strconv.FormatBool(remoteWrite.QueueMaxSamplesValid)
	resource.Metadata["remote_write_queue_max_samples_per_send"] = strconv.Itoa(remoteWrite.QueueMaxSamplesPerSend)
	queueIssueCount := kubernetesRemoteWriteQueueIssueCount(remoteWrite)
	resource.Metadata["remote_write_queue_invalid"] = strconv.FormatBool(queueIssueCount > 0)
	resource.Metadata["remote_write_queue_issue_count"] = strconv.Itoa(queueIssueCount)
	resource.Metadata["remote_write_metadata_config_declared"] = strconv.FormatBool(remoteWrite.MetadataConfigDeclared)
}

func kubernetesRemoteWriteQueueIssueCount(remoteWrite kubernetesRemoteWrite) int {
	issues := 0
	for _, setting := range []struct {
		declared bool
		valid    bool
		value    int
	}{
		{remoteWrite.QueueCapacityDeclared, remoteWrite.QueueCapacityValid, remoteWrite.QueueCapacity},
		{remoteWrite.QueueMinShardsDeclared, remoteWrite.QueueMinShardsValid, remoteWrite.QueueMinShards},
		{remoteWrite.QueueMaxShardsDeclared, remoteWrite.QueueMaxShardsValid, remoteWrite.QueueMaxShards},
		{remoteWrite.QueueMaxSamplesDeclared, remoteWrite.QueueMaxSamplesValid, remoteWrite.QueueMaxSamplesPerSend},
	} {
		if setting.declared && (!setting.valid || setting.value <= 0) {
			issues++
		}
	}
	if remoteWrite.QueueMinShardsDeclared && remoteWrite.QueueMinShardsValid && remoteWrite.QueueMaxShardsDeclared && remoteWrite.QueueMaxShardsValid && remoteWrite.QueueMinShards > remoteWrite.QueueMaxShards {
		issues++
	}
	return issues
}

func addKubernetesRemoteWriteTopology(resources map[string]model.Resource, relationships map[string]model.Relationship, workloads []kubernetesPrometheusResource, candidates []kubernetesRemoteWriteResource, namespaceLabels map[string]map[string]string, now time.Time) {
	if len(workloads) == 0 {
		return
	}
	selectedByWorkload := map[string][]model.Resource{}
	for index := range candidates {
		candidate := candidates[index]
		selectedCount := 0
		allKnown := true
		for _, workload := range workloads {
			resourceMatches, resourceKnown := kubernetesLabelSelectorMatches(workload.Object.RemoteWriteSelection.ResourceSelector, candidate.Resource.Labels)
			if !resourceKnown {
				allKnown = false
				continue
			}
			if !resourceMatches {
				continue
			}
			namespaceMatches, namespaceKnown := kubernetesNamespaceSelectorMatches(workload.Object.RemoteWriteSelection.NamespaceSelector, workload.Object.Namespace, candidate.Object.Namespace, namespaceLabels)
			if !namespaceKnown {
				allKnown = false
				continue
			}
			if !namespaceMatches {
				continue
			}
			relationship := kubernetesRelationship(workload.Resource.ID, candidate.Resource.ID, model.RelationshipUses, now)
			relationship.Metadata = map[string]string{"usage_kind": "RemoteWrite", "remote_write_origin": "crd", "selection_kind": "RemoteWrite"}
			relationships[relationship.ID] = relationship
			selectedByWorkload[workload.Resource.ID] = append(selectedByWorkload[workload.Resource.ID], candidate.Resource)
			selectedCount++
		}
		updated := resources[candidate.Resource.ID]
		updated.Metadata["remote_write_selection_evaluable"] = strconv.FormatBool(selectedCount > 0 || allKnown)
		updated.Metadata["remote_write_selected_count"] = strconv.Itoa(selectedCount)
		resources[updated.ID] = updated
	}
	for _, workload := range workloads {
		inline := make([]model.Resource, 0)
		for _, resource := range resources {
			if resource.Type == model.ResourceTypeExporter && resource.Metadata["remote_write_origin"] == "inline" && resource.Metadata["remote_write_parent_id"] == workload.Resource.ID {
				inline = append(inline, resource)
			}
		}
		selected := selectedByWorkload[workload.Resource.ID]
		names := map[string]int{}
		for _, resource := range append(inline, selected...) {
			if resource.Metadata["remote_write_name_declared"] == "true" {
				names[resource.Metadata["remote_write_name"]]++
			}
		}
		updated := resources[workload.Resource.ID]
		updated.Metadata["remote_write_selected_crd_count"] = strconv.Itoa(len(selected))
		updated.Metadata["remote_write_effective_count"] = strconv.Itoa(len(inline) + len(selected))
		updated.Metadata["remote_write_duplicate_name_count"] = strconv.Itoa(duplicateRemoteWriteNameCount(names))
		updated.Metadata["prometheus_remote_write_count"] = strconv.Itoa(len(inline) + len(selected))
		resources[updated.ID] = updated
	}
}

func duplicateRemoteWriteNameCount(names map[string]int) int {
	duplicates := 0
	for _, count := range names {
		if count > 1 {
			duplicates++
		}
	}
	return duplicates
}
