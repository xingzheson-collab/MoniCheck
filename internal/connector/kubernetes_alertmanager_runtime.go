package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

var alertmanagerManagedContainerNames = map[string]bool{
	"alertmanager":    true,
	"config-reloader": true,
	"thanos-sidecar":  true,
}

var alertmanagerManagedInitContainerNames = map[string]bool{"init-config-reloader": true}

func populateKubernetesAlertmanagerRuntimeObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesRuntime(spec, alertmanagerManagedContainerNames, alertmanagerManagedInitContainerNames)
	object.AlertmanagerRuntimeMetadata = true
	object.AlertmanagerListenLocalEnabled = summary.ListenLocalEnabled
	object.AlertmanagerListenLocalDeclared = summary.ListenLocalDeclared
	object.AlertmanagerListenLocalValid = summary.ListenLocalValid
	object.AlertmanagerLogLevel = summary.LogLevel
	object.AlertmanagerLogLevelDeclared = summary.LogLevelDeclared
	object.AlertmanagerLogLevelValid = summary.LogLevelValid
	object.AlertmanagerLogFormat = summary.LogFormat
	object.AlertmanagerLogFormatDeclared = summary.LogFormatDeclared
	object.AlertmanagerLogFormatValid = summary.LogFormatValid
	object.AlertmanagerContainersDeclared = summary.ContainersDeclared
	object.AlertmanagerSidecarContainerCount = summary.SidecarContainerCount
	object.AlertmanagerContainerInvalidCount = summary.ContainerInvalidCount
	object.AlertmanagerInitContainersDeclared = summary.InitContainersDeclared
	object.AlertmanagerInitContainerInvalidCount = summary.InitContainerInvalidCount
	object.AlertmanagerManagedContainerOverrideCount = summary.ManagedContainerOverrideCount
	object.AlertmanagerManagedInitContainerOverrideCount = summary.ManagedInitContainerOverrideCount
}

func populateKubernetesAlertmanagerRuntimeMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_runtime_metadata"] = strconv.FormatBool(object.AlertmanagerRuntimeMetadata)
	resource.Metadata["alertmanager_listen_local_declared"] = strconv.FormatBool(object.AlertmanagerListenLocalDeclared)
	resource.Metadata["alertmanager_listen_local_valid"] = strconv.FormatBool(object.AlertmanagerListenLocalValid)
	resource.Metadata["alertmanager_listen_local_enabled"] = strconv.FormatBool(object.AlertmanagerListenLocalEnabled)
	resource.Metadata["alertmanager_log_level_declared"] = strconv.FormatBool(object.AlertmanagerLogLevelDeclared)
	resource.Metadata["alertmanager_log_level_valid"] = strconv.FormatBool(object.AlertmanagerLogLevelValid)
	resource.Metadata["alertmanager_log_level"] = object.AlertmanagerLogLevel
	resource.Metadata["alertmanager_log_format_declared"] = strconv.FormatBool(object.AlertmanagerLogFormatDeclared)
	resource.Metadata["alertmanager_log_format_valid"] = strconv.FormatBool(object.AlertmanagerLogFormatValid)
	resource.Metadata["alertmanager_log_format"] = object.AlertmanagerLogFormat
	resource.Metadata["alertmanager_containers_declared"] = strconv.FormatBool(object.AlertmanagerContainersDeclared)
	resource.Metadata["alertmanager_sidecar_container_count"] = strconv.Itoa(object.AlertmanagerSidecarContainerCount)
	resource.Metadata["alertmanager_container_invalid_count"] = strconv.Itoa(object.AlertmanagerContainerInvalidCount)
	resource.Metadata["alertmanager_init_containers_declared"] = strconv.FormatBool(object.AlertmanagerInitContainersDeclared)
	resource.Metadata["alertmanager_init_container_invalid_count"] = strconv.Itoa(object.AlertmanagerInitContainerInvalidCount)
	resource.Metadata["alertmanager_managed_container_override_count"] = strconv.Itoa(object.AlertmanagerManagedContainerOverrideCount)
	resource.Metadata["alertmanager_managed_init_container_override_count"] = strconv.Itoa(object.AlertmanagerManagedInitContainerOverrideCount)
}
