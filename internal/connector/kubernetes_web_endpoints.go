package connector

import (
	"strconv"
	"strings"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesPrometheusWebEndpointObject(object *kubernetesObject, spec *yaml.Node) {
	object.PrometheusRemoteWriteReceiver = yamlBoolValue(yamlMappingValue(spec, "enableRemoteWriteReceiver"))
	object.PrometheusOTLPConfigDeclared = yamlValueDeclared(yamlMappingValue(spec, "otlp"))
	object.PrometheusOTLPReceiver = yamlBoolValue(yamlMappingValue(spec, "enableOTLPReceiver")) || object.PrometheusOTLPConfigDeclared
	if object.Kind == "Prometheus" {
		object.PrometheusAdminAPIEnabled = yamlBoolValue(yamlMappingValue(spec, "enableAdminAPI"))
	}
	remoteSupported, evaluable := kubernetesPrometheusVersionAtLeast(object.PrometheusVersion, 2, 33)
	object.PrometheusReceiverVersionEvaluable = evaluable
	object.PrometheusRemoteReceiverUnsupported = evaluable && object.PrometheusRemoteWriteReceiver && !remoteSupported
	otlpSupported, _ := kubernetesPrometheusVersionAtLeast(object.PrometheusVersion, 2, 47)
	object.PrometheusOTLPReceiverUnsupported = evaluable && object.PrometheusOTLPReceiver && !otlpSupported
	web := yamlMappingValue(spec, "web")
	object.PrometheusWebDeclared = yamlValueDeclared(web)
	if object.PrometheusWebDeclared {
		if web.Kind != yaml.MappingNode {
			object.PrometheusWebInvalidSettingCount++
		} else {
			maxConnections := yamlMappingValue(web, "maxConnections")
			object.PrometheusWebMaxConnectionsDeclared = yamlValueDeclared(maxConnections)
			if object.PrometheusWebMaxConnectionsDeclared {
				value, err := strconv.ParseInt(strings.TrimSpace(maxConnections.Value), 10, 64)
				if err != nil || value < 0 {
					object.PrometheusWebInvalidSettingCount++
				} else {
					object.PrometheusWebMaxConnectionsValid = true
					object.PrometheusWebMaxConnections = value
				}
			}
		}
	}
	externalURL := yamlScalarValue(yamlMappingValue(spec, "externalUrl"))
	object.PrometheusExternalURLDeclared = externalURL != ""
	if object.PrometheusExternalURLDeclared {
		object.PrometheusExternalURLScheme, object.PrometheusExternalURLValid = safeRemoteWriteURLMetadata(externalURL)
	}
}

func populateKubernetesPrometheusWebEndpointMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_admin_api_enabled"] = strconv.FormatBool(object.PrometheusAdminAPIEnabled)
	resource.Metadata["prometheus_remote_write_receiver_enabled"] = strconv.FormatBool(object.PrometheusRemoteWriteReceiver)
	resource.Metadata["prometheus_otlp_receiver_enabled"] = strconv.FormatBool(object.PrometheusOTLPReceiver)
	resource.Metadata["prometheus_otlp_config_declared"] = strconv.FormatBool(object.PrometheusOTLPConfigDeclared)
	resource.Metadata["prometheus_receiver_version_evaluable"] = strconv.FormatBool(object.PrometheusReceiverVersionEvaluable)
	resource.Metadata["prometheus_remote_write_receiver_version_unsupported"] = strconv.FormatBool(object.PrometheusRemoteReceiverUnsupported)
	resource.Metadata["prometheus_otlp_receiver_version_unsupported"] = strconv.FormatBool(object.PrometheusOTLPReceiverUnsupported)
	resource.Metadata["prometheus_web_declared"] = strconv.FormatBool(object.PrometheusWebDeclared)
	resource.Metadata["prometheus_web_invalid_setting_count"] = strconv.Itoa(object.PrometheusWebInvalidSettingCount)
	resource.Metadata["prometheus_web_max_connections_declared"] = strconv.FormatBool(object.PrometheusWebMaxConnectionsDeclared)
	resource.Metadata["prometheus_web_max_connections_valid"] = strconv.FormatBool(object.PrometheusWebMaxConnectionsValid)
	if object.PrometheusWebMaxConnectionsValid {
		resource.Metadata["prometheus_web_max_connections"] = strconv.FormatInt(object.PrometheusWebMaxConnections, 10)
	}
	resource.Metadata["prometheus_external_url_declared"] = strconv.FormatBool(object.PrometheusExternalURLDeclared)
	resource.Metadata["prometheus_external_url_valid"] = strconv.FormatBool(object.PrometheusExternalURLValid)
	resource.Metadata["prometheus_external_url_scheme"] = object.PrometheusExternalURLScheme
}

func kubernetesPrometheusVersionAtLeast(raw string, minimumMajor int, minimumMinor int) (bool, bool) {
	version := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	versionParts := strings.SplitN(version, "-", 2)
	parts := strings.Split(versionParts[0], ".")
	if len(parts) < 2 {
		return false, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
		return false, false
	}
	if major != minimumMajor {
		return major > minimumMajor, true
	}
	if minor != minimumMinor {
		return minor > minimumMinor, true
	}
	patch := 0
	if len(parts) >= 3 {
		var patchErr error
		patch, patchErr = strconv.Atoi(parts[2])
		if patchErr != nil || patch < 0 {
			return false, false
		}
	}
	return patch > 0 || len(versionParts) == 1, true
}
