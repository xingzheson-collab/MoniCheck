package connector

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerClusterObject(object *kubernetesObject, spec *yaml.Node) {
	object.AlertmanagerClusterMetadata = true
	peers := yamlMappingValue(spec, "additionalPeers")
	object.AlertmanagerAdditionalPeersDeclared = yamlValueDeclared(peers)
	peerCounts := map[string]int{}
	if object.AlertmanagerAdditionalPeersDeclared {
		if peers.Kind != yaml.SequenceNode {
			object.AlertmanagerAdditionalPeerInvalidCount = 1
		} else {
			for _, peer := range peers.Content {
				if _, valid, _, _ := parseAlertmanagerClusterAddress(peer); !valid {
					object.AlertmanagerAdditionalPeerInvalidCount++
					continue
				}
				peerCounts[strings.TrimSpace(peer.Value)]++
				object.AlertmanagerAdditionalPeerCount++
			}
		}
	}
	advertiseAddress := yamlMappingValue(spec, "clusterAdvertiseAddress")
	object.AlertmanagerClusterAdvertiseAddressDeclared, object.AlertmanagerClusterAdvertiseAddressValid, object.AlertmanagerClusterAdvertiseAddressLoopback, object.AlertmanagerClusterAdvertiseAddressUnspecified = parseAlertmanagerClusterAddress(advertiseAddress)
	for _, count := range peerCounts {
		if count > 1 {
			object.AlertmanagerAdditionalPeerDuplicateCount += count - 1
		}
	}

	for _, field := range []string{"clusterGossipInterval", "clusterPushpullInterval", "clusterPeerTimeout"} {
		setting := parseKubernetesDurationSetting(yamlMappingValue(spec, field))
		if !setting.Declared {
			continue
		}
		object.AlertmanagerClusterTimingDeclaredCount++
		if !setting.Valid {
			object.AlertmanagerClusterTimingInvalidCount++
		}
	}

	object.AlertmanagerForceClusterModeEnabled, object.AlertmanagerForceClusterModeDeclared, object.AlertmanagerForceClusterModeValid = parseKubernetesBooleanSetting(yamlMappingValue(spec, "forceEnableClusterMode"))
	clusterLabel := yamlMappingValue(spec, "clusterLabel")
	if yamlValueDeclared(clusterLabel) {
		object.AlertmanagerClusterLabelValid = clusterLabel.Kind == yaml.ScalarNode
		object.AlertmanagerClusterLabelInvalid = !object.AlertmanagerClusterLabelValid
		object.AlertmanagerClusterLabelDeclared = object.AlertmanagerClusterLabelValid && strings.TrimSpace(clusterLabel.Value) != ""
	}
}

func parseAlertmanagerClusterAddress(node *yaml.Node) (declared, valid, loopback, unspecified bool) {
	declared = yamlValueDeclared(node)
	if !declared || node.Kind != yaml.ScalarNode {
		return declared, false, false, false
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(node.Value))
	if err != nil || host == "" {
		return true, false, false, false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return true, false, false, false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return true, true, address.IsLoopback(), address.IsUnspecified()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(validation.IsDNS1123Subdomain(host)) > 0 {
		return true, false, false, false
	}
	return true, true, host == "localhost" || strings.HasSuffix(host, ".localhost"), false
}

func populateKubernetesAlertmanagerClusterMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_cluster_metadata"] = strconv.FormatBool(object.AlertmanagerClusterMetadata)
	resource.Metadata["alertmanager_additional_peers_declared"] = strconv.FormatBool(object.AlertmanagerAdditionalPeersDeclared)
	resource.Metadata["alertmanager_additional_peer_count"] = strconv.Itoa(object.AlertmanagerAdditionalPeerCount)
	resource.Metadata["alertmanager_additional_peer_invalid_count"] = strconv.Itoa(object.AlertmanagerAdditionalPeerInvalidCount)
	resource.Metadata["alertmanager_additional_peer_duplicate_count"] = strconv.Itoa(object.AlertmanagerAdditionalPeerDuplicateCount)
	resource.Metadata["alertmanager_cluster_timing_declared_count"] = strconv.Itoa(object.AlertmanagerClusterTimingDeclaredCount)
	resource.Metadata["alertmanager_cluster_timing_invalid_count"] = strconv.Itoa(object.AlertmanagerClusterTimingInvalidCount)
	resource.Metadata["alertmanager_force_cluster_mode_declared"] = strconv.FormatBool(object.AlertmanagerForceClusterModeDeclared)
	resource.Metadata["alertmanager_force_cluster_mode_valid"] = strconv.FormatBool(object.AlertmanagerForceClusterModeValid)
	resource.Metadata["alertmanager_force_cluster_mode_enabled"] = strconv.FormatBool(object.AlertmanagerForceClusterModeEnabled)
	resource.Metadata["alertmanager_cluster_label_declared"] = strconv.FormatBool(object.AlertmanagerClusterLabelDeclared)
	resource.Metadata["alertmanager_cluster_label_valid"] = strconv.FormatBool(object.AlertmanagerClusterLabelValid)
	resource.Metadata["alertmanager_cluster_label_invalid"] = strconv.FormatBool(object.AlertmanagerClusterLabelInvalid)
	resource.Metadata["alertmanager_cluster_advertise_address_declared"] = strconv.FormatBool(object.AlertmanagerClusterAdvertiseAddressDeclared)
	resource.Metadata["alertmanager_cluster_advertise_address_valid"] = strconv.FormatBool(object.AlertmanagerClusterAdvertiseAddressValid)
	resource.Metadata["alertmanager_cluster_advertise_address_loopback"] = strconv.FormatBool(object.AlertmanagerClusterAdvertiseAddressLoopback)
	resource.Metadata["alertmanager_cluster_advertise_address_unspecified"] = strconv.FormatBool(object.AlertmanagerClusterAdvertiseAddressUnspecified)
}
