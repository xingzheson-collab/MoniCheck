package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerGRPCTLSObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerGRPCTLSMetadata = true
	tlsConfig := yamlMappingValue(spec, "grpcServerTlsConfig")
	object.ThanosRulerGRPCTLSDeclared = yamlValueDeclared(tlsConfig)
	if !object.ThanosRulerGRPCTLSDeclared {
		return
	}
	if tlsConfig.Kind != yaml.MappingNode {
		object.ThanosRulerGRPCTLSInvalidSettingCount = 1
		return
	}

	certValid := parseKubernetesNonEmptyScalar(yamlMappingValue(tlsConfig, "certFile"))
	keyValid := parseKubernetesNonEmptyScalar(yamlMappingValue(tlsConfig, "keyFile"))
	parseKubernetesOptionalNonEmptyScalar(yamlMappingValue(tlsConfig, "caFile"), &object.ThanosRulerGRPCTLSInvalidSettingCount)
	if !certValid {
		object.ThanosRulerGRPCTLSInvalidSettingCount++
	}
	if !keyValid {
		object.ThanosRulerGRPCTLSInvalidSettingCount++
	}

	if minVersion := yamlMappingValue(tlsConfig, "minVersion"); yamlValueDeclared(minVersion) {
		valid := minVersion.Kind == yaml.ScalarNode
		if valid {
			_, valid = map[string]bool{"TLS10": true, "TLS11": true, "TLS12": true, "TLS13": true}[strings.TrimSpace(minVersion.Value)]
		}
		if !valid {
			object.ThanosRulerGRPCTLSInvalidSettingCount++
		}
	}
	for _, name := range []string{"cipherSuites", "curves", "curvePreferences"} {
		if values := yamlMappingValue(tlsConfig, name); yamlValueDeclared(values) && !validKubernetesNonEmptyStringSequence(values) {
			object.ThanosRulerGRPCTLSInvalidSettingCount++
		}
	}
	for _, name := range []string{"ca", "cert", "keySecret", "maxVersion", "preferServerCipherSuites", "client_ca", "clientCA", "clientCAFile", "clientAuthType"} {
		if yamlValueDeclared(yamlMappingValue(tlsConfig, name)) {
			object.ThanosRulerGRPCTLSUnsupportedSettingCount++
		}
	}
	object.ThanosRulerGRPCTLSComplete = certValid && keyValid && object.ThanosRulerGRPCTLSInvalidSettingCount == 0
}

func parseKubernetesNonEmptyScalar(node *yaml.Node) bool {
	if !yamlValueDeclared(node) {
		return false
	}
	if node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "" {
		return false
	}
	return true
}

func parseKubernetesOptionalNonEmptyScalar(node *yaml.Node, invalidCount *int) {
	if yamlValueDeclared(node) && (node.Kind != yaml.ScalarNode || strings.TrimSpace(node.Value) == "") {
		*invalidCount++
	}
}

func validKubernetesNonEmptyStringSequence(node *yaml.Node) bool {
	if node.Kind != yaml.SequenceNode {
		return false
	}
	seen := map[string]bool{}
	for _, item := range node.Content {
		value := strings.TrimSpace(yamlScalarValue(item))
		if item.Kind != yaml.ScalarNode || value == "" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func populateKubernetesThanosRulerGRPCTLSMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_grpc_tls_metadata"] = strconv.FormatBool(object.ThanosRulerGRPCTLSMetadata)
	resource.Metadata["thanos_ruler_grpc_tls_declared"] = strconv.FormatBool(object.ThanosRulerGRPCTLSDeclared)
	resource.Metadata["thanos_ruler_grpc_tls_complete"] = strconv.FormatBool(object.ThanosRulerGRPCTLSComplete)
	resource.Metadata["thanos_ruler_grpc_tls_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerGRPCTLSInvalidSettingCount)
	resource.Metadata["thanos_ruler_grpc_tls_unsupported_setting_count"] = strconv.Itoa(object.ThanosRulerGRPCTLSUnsupportedSettingCount)
}
