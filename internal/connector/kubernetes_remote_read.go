package connector

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func parseKubernetesRemoteReads(node *yaml.Node) []kubernetesRemoteRead {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	result := make([]kubernetesRemoteRead, 0, len(node.Content))
	for index, definition := range node.Content {
		result = append(result, parseKubernetesRemoteRead(definition, index))
	}
	return result
}

func parseKubernetesRemoteRead(node *yaml.Node, index int) kubernetesRemoteRead {
	remoteRead := kubernetesRemoteRead{
		Name:                 yamlScalarValue(yamlMappingValue(node, "name")),
		Index:                index,
		RequiredMatcherCount: yamlMappingLength(yamlMappingValue(node, "requiredMatchers")),
		RemoteTimeout:        yamlScalarValue(yamlMappingValue(node, "remoteTimeout")),
		HeaderCount:          yamlMappingLength(yamlMappingValue(node, "headers")),
	}
	endpoint := yamlScalarValue(yamlMappingValue(node, "url"))
	remoteRead.DestinationDeclared = endpoint != ""
	remoteRead.URLScheme, remoteRead.URLValid = safeRemoteWriteURLMetadata(endpoint)
	remoteRead.ReadRecent, remoteRead.ReadRecentDeclared = yamlBoolValueWithDefault(yamlMappingValue(node, "readRecent"), false)
	remoteRead.FilterExternalLabels, remoteRead.FilterExternalDeclared = yamlBoolValueWithDefault(yamlMappingValue(node, "filterExternalLabels"), true)
	remoteRead.TLSConfigDeclared = yamlValueDeclared(yamlMappingValue(node, "tlsConfig"))
	remoteRead.TLSInsecureSkipVerify = yamlBoolValue(yamlMappingValue(yamlMappingValue(node, "tlsConfig"), "insecureSkipVerify"))
	remoteRead.AuthorizationDeclared = yamlValueDeclared(yamlMappingValue(node, "authorization"))
	remoteRead.BasicAuthDeclared = yamlValueDeclared(yamlMappingValue(node, "basicAuth"))
	remoteRead.OAuth2Declared = yamlValueDeclared(yamlMappingValue(node, "oauth2"))
	remoteRead.BearerTokenDeclared = yamlValueDeclared(yamlMappingValue(node, "bearerToken"))
	remoteRead.BearerTokenFileDeclared = yamlValueDeclared(yamlMappingValue(node, "bearerTokenFile"))
	for _, declared := range []bool{remoteRead.AuthorizationDeclared, remoteRead.BasicAuthDeclared, remoteRead.OAuth2Declared, remoteRead.BearerTokenDeclared, remoteRead.BearerTokenFileDeclared} {
		if declared {
			remoteRead.AuthMethodCount++
		}
	}
	remoteRead.ProxyDeclared = yamlValueDeclared(yamlMappingValue(node, "proxyUrl")) || yamlBoolValue(yamlMappingValue(node, "proxyFromEnvironment")) || yamlValueDeclared(yamlMappingValue(node, "proxyConnectHeader"))
	return remoteRead
}

func yamlBoolValueWithDefault(node *yaml.Node, defaultValue bool) (bool, bool) {
	if node == nil || node.Tag == "!!null" {
		return defaultValue, false
	}
	value, err := strconv.ParseBool(strings.TrimSpace(node.Value))
	if err != nil {
		return defaultValue, true
	}
	return value, true
}

func addKubernetesRemoteReadResources(resources map[string]model.Resource, relationships map[string]model.Relationship, workload model.Resource, object kubernetesObject, instance string, now time.Time) {
	names := map[string]int{}
	for _, remoteRead := range object.RemoteReads {
		resource := newKubernetesRemoteReadResource(workload, remoteRead, instance, now)
		resources[resource.ID] = resource
		relationship := kubernetesRelationship(workload.ID, resource.ID, model.RelationshipUses, now)
		relationship.Metadata = map[string]string{"usage_kind": "RemoteRead"}
		relationships[relationship.ID] = relationship
		if remoteRead.Name != "" {
			names[remoteRead.Name]++
		}
	}
	updated := resources[workload.ID]
	updated.Metadata["prometheus_remote_read_count"] = strconv.Itoa(len(object.RemoteReads))
	updated.Metadata["remote_read_duplicate_name_count"] = strconv.Itoa(duplicateDeclaredNameCount(names))
	resources[workload.ID] = updated
}

func newKubernetesRemoteReadResource(workload model.Resource, remoteRead kubernetesRemoteRead, instance string, now time.Time) model.Resource {
	externalID := fmt.Sprintf("%s:remote-read:%d", workload.Source.ExternalID, remoteRead.Index)
	name := remoteRead.Name
	if name == "" {
		name = fmt.Sprintf("remote-read-%d", remoteRead.Index+1)
	}
	resource := kubernetesManifestResource(model.ResourceTypeDatasource, name, instance, externalID, now)
	resource.Metadata["kubernetes_kind"] = "RemoteRead"
	resource.Metadata["namespace"] = workload.Metadata["namespace"]
	resource.Metadata["remote_read_parent_id"] = workload.ID
	resource.Metadata["remote_read_parent_name"] = workload.Name
	resource.Metadata["remote_read_parent_kind"] = workload.Metadata["kubernetes_kind"]
	resource.Metadata["remote_read_name"] = remoteRead.Name
	resource.Metadata["remote_read_name_declared"] = strconv.FormatBool(remoteRead.Name != "")
	resource.Metadata["remote_read_destination_declared"] = strconv.FormatBool(remoteRead.DestinationDeclared)
	resource.Metadata["remote_read_url_scheme"] = remoteRead.URLScheme
	resource.Metadata["remote_read_url_valid"] = strconv.FormatBool(remoteRead.URLValid)
	resource.Metadata["remote_read_required_matcher_count"] = strconv.Itoa(remoteRead.RequiredMatcherCount)
	resource.Metadata["remote_read_remote_timeout"] = remoteRead.RemoteTimeout
	resource.Metadata["remote_read_header_count"] = strconv.Itoa(remoteRead.HeaderCount)
	resource.Metadata["remote_read_read_recent"] = strconv.FormatBool(remoteRead.ReadRecent)
	resource.Metadata["remote_read_read_recent_declared"] = strconv.FormatBool(remoteRead.ReadRecentDeclared)
	resource.Metadata["remote_read_filter_external_labels"] = strconv.FormatBool(remoteRead.FilterExternalLabels)
	resource.Metadata["remote_read_filter_external_labels_declared"] = strconv.FormatBool(remoteRead.FilterExternalDeclared)
	resource.Metadata["remote_read_tls_config_declared"] = strconv.FormatBool(remoteRead.TLSConfigDeclared)
	resource.Metadata["remote_read_tls_insecure"] = strconv.FormatBool(remoteRead.TLSInsecureSkipVerify)
	resource.Metadata["remote_read_authorization_declared"] = strconv.FormatBool(remoteRead.AuthorizationDeclared)
	resource.Metadata["remote_read_basic_auth_declared"] = strconv.FormatBool(remoteRead.BasicAuthDeclared)
	resource.Metadata["remote_read_oauth2_declared"] = strconv.FormatBool(remoteRead.OAuth2Declared)
	resource.Metadata["remote_read_cleartext_bearer_declared"] = strconv.FormatBool(remoteRead.BearerTokenDeclared)
	resource.Metadata["remote_read_deprecated_bearer_file_declared"] = strconv.FormatBool(remoteRead.BearerTokenFileDeclared)
	resource.Metadata["remote_read_auth_method_count"] = strconv.Itoa(remoteRead.AuthMethodCount)
	resource.Metadata["remote_read_proxy_declared"] = strconv.FormatBool(remoteRead.ProxyDeclared)
	resource.Metadata[model.MetadataDatasourceType] = "prometheus"
	resource.Metadata[model.MetadataDatasourceHealthEvaluable] = "false"
	return resource
}

func duplicateDeclaredNameCount(names map[string]int) int {
	count := 0
	for _, occurrences := range names {
		if occurrences > 1 {
			count += occurrences - 1
		}
	}
	return count
}
