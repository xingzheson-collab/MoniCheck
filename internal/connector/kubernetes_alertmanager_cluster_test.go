package connector

import (
	"testing"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func TestPopulateKubernetesAlertmanagerClusterMetadata(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(`spec:
  additionalPeers:
    - am-one.example:9094
    - am-one.example:9094
    - ""
  clusterGossipInterval: 200ms
  clusterPushpullInterval: broken
  clusterPeerTimeout: 15s
  clusterAdvertiseAddress: "[2001:db8::10]:9094"
  forceEnableClusterMode: true
  clusterLabel: shared-production
`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	object := kubernetesObject{}
	populateKubernetesAlertmanagerClusterObject(&object, yamlMappingValue(document.Content[0], "spec"))
	resource := model.Resource{Metadata: map[string]string{}}
	populateKubernetesAlertmanagerClusterMetadata(&resource, object)

	expected := map[string]string{
		"alertmanager_additional_peer_count":              "2",
		"alertmanager_additional_peer_invalid_count":      "1",
		"alertmanager_additional_peer_duplicate_count":    "1",
		"alertmanager_cluster_timing_declared_count":      "3",
		"alertmanager_cluster_timing_invalid_count":       "1",
		"alertmanager_cluster_advertise_address_declared": "true",
		"alertmanager_cluster_advertise_address_valid":    "true",
		"alertmanager_force_cluster_mode_enabled":         "true",
		"alertmanager_cluster_label_declared":             "true",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got metadata %#v", key, value, resource.Metadata)
		}
	}
}

func TestPopulateKubernetesAlertmanagerClusterRejectsMalformedStructures(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(`spec:
  additionalPeers: peer.example:9094
  clusterGossipInterval: {}
  clusterAdvertiseAddress: alerts.example.invalid
  forceEnableClusterMode: enabled
  clusterLabel: {}
`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	object := kubernetesObject{}
	populateKubernetesAlertmanagerClusterObject(&object, yamlMappingValue(document.Content[0], "spec"))
	if object.AlertmanagerAdditionalPeerInvalidCount != 1 || object.AlertmanagerClusterTimingInvalidCount != 1 || object.AlertmanagerClusterAdvertiseAddressValid || object.AlertmanagerForceClusterModeValid || object.AlertmanagerClusterLabelValid {
		t.Fatalf("unexpected malformed cluster metadata: %#v", object)
	}
}

func TestParseAlertmanagerClusterAddress(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		valid       bool
		loopback    bool
		unspecified bool
	}{
		{name: "DNS", value: "alertmanager.example:9094", valid: true},
		{name: "absolute DNS", value: "alertmanager.example.:9094", valid: true},
		{name: "IPv4", value: "192.0.2.10:9094", valid: true},
		{name: "IPv6", value: "[2001:db8::10]:9094", valid: true},
		{name: "loopback IPv4", value: "127.0.0.1:9094", valid: true, loopback: true},
		{name: "localhost", value: "peer.localhost:9094", valid: true, loopback: true},
		{name: "unspecified IPv4", value: "0.0.0.0:9094", valid: true, unspecified: true},
		{name: "unspecified IPv6", value: "[::]:9094", valid: true, unspecified: true},
		{name: "missing port", value: "alertmanager.example", valid: false},
		{name: "zero port", value: "alertmanager.example:0", valid: false},
		{name: "oversized port", value: "alertmanager.example:65536", valid: false},
		{name: "empty host", value: ":9094", valid: false},
		{name: "invalid DNS", value: "bad_host:9094", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := &yaml.Node{Kind: yaml.ScalarNode, Value: test.value}
			declared, valid, loopback, unspecified := parseAlertmanagerClusterAddress(node)
			if !declared || valid != test.valid || loopback != test.loopback || unspecified != test.unspecified {
				t.Fatalf("unexpected address metadata for %q: declared=%t valid=%t loopback=%t unspecified=%t", test.value, declared, valid, loopback, unspecified)
			}
		})
	}
}
