package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

var prometheusManagedContainerNames = map[string]bool{
	"prometheus":      true,
	"config-reloader": true,
	"thanos-sidecar":  true,
}

var prometheusManagedInitContainerNames = map[string]bool{"init-config-reloader": true}

func populateKubernetesPrometheusRuntimeObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesRuntime(spec, prometheusManagedContainerNames, prometheusManagedInitContainerNames)
	object.PrometheusRuntimeMetadata = true
	object.PrometheusListenLocalEnabled = summary.ListenLocalEnabled
	object.PrometheusListenLocalDeclared = summary.ListenLocalDeclared
	object.PrometheusListenLocalValid = summary.ListenLocalValid
	object.PrometheusLogLevel = summary.LogLevel
	object.PrometheusLogLevelDeclared = summary.LogLevelDeclared
	object.PrometheusLogLevelValid = summary.LogLevelValid
	object.PrometheusLogFormat = summary.LogFormat
	object.PrometheusLogFormatDeclared = summary.LogFormatDeclared
	object.PrometheusLogFormatValid = summary.LogFormatValid
	object.PrometheusContainersDeclared = summary.ContainersDeclared
	object.PrometheusSidecarContainerCount = summary.SidecarContainerCount
	object.PrometheusContainerInvalidCount = summary.ContainerInvalidCount
	object.PrometheusInitContainersDeclared = summary.InitContainersDeclared
	object.PrometheusInitContainerInvalidCount = summary.InitContainerInvalidCount
	object.PrometheusManagedContainerOverrideCount = summary.ManagedContainerOverrideCount
	object.PrometheusManagedInitContainerOverrideCount = summary.ManagedInitContainerOverrideCount
}

func populateKubernetesPrometheusRuntimeMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_runtime_metadata"] = strconv.FormatBool(object.PrometheusRuntimeMetadata)
	resource.Metadata["prometheus_listen_local_declared"] = strconv.FormatBool(object.PrometheusListenLocalDeclared)
	resource.Metadata["prometheus_listen_local_valid"] = strconv.FormatBool(object.PrometheusListenLocalValid)
	resource.Metadata["prometheus_listen_local_enabled"] = strconv.FormatBool(object.PrometheusListenLocalEnabled)
	resource.Metadata["prometheus_log_level_declared"] = strconv.FormatBool(object.PrometheusLogLevelDeclared)
	resource.Metadata["prometheus_log_level_valid"] = strconv.FormatBool(object.PrometheusLogLevelValid)
	resource.Metadata["prometheus_log_level"] = object.PrometheusLogLevel
	resource.Metadata["prometheus_log_format_declared"] = strconv.FormatBool(object.PrometheusLogFormatDeclared)
	resource.Metadata["prometheus_log_format_valid"] = strconv.FormatBool(object.PrometheusLogFormatValid)
	resource.Metadata["prometheus_log_format"] = object.PrometheusLogFormat
	resource.Metadata["prometheus_containers_declared"] = strconv.FormatBool(object.PrometheusContainersDeclared)
	resource.Metadata["prometheus_sidecar_container_count"] = strconv.Itoa(object.PrometheusSidecarContainerCount)
	resource.Metadata["prometheus_container_invalid_count"] = strconv.Itoa(object.PrometheusContainerInvalidCount)
	resource.Metadata["prometheus_init_containers_declared"] = strconv.FormatBool(object.PrometheusInitContainersDeclared)
	resource.Metadata["prometheus_init_container_invalid_count"] = strconv.Itoa(object.PrometheusInitContainerInvalidCount)
	resource.Metadata["prometheus_managed_container_override_count"] = strconv.Itoa(object.PrometheusManagedContainerOverrideCount)
	resource.Metadata["prometheus_managed_init_container_override_count"] = strconv.Itoa(object.PrometheusManagedInitContainerOverrideCount)
}
