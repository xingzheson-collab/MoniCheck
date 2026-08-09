package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

var thanosRulerManagedContainerNames = map[string]bool{
	"thanos-ruler":    true,
	"config-reloader": true,
}

var thanosRulerManagedInitContainerNames = map[string]bool{"init-config-reloader": true}

func populateKubernetesThanosRulerRuntimeObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesRuntime(spec, thanosRulerManagedContainerNames, thanosRulerManagedInitContainerNames)
	object.ThanosRulerRuntimeMetadata = true
	object.ThanosRulerListenLocalEnabled = summary.ListenLocalEnabled
	object.ThanosRulerListenLocalDeclared = summary.ListenLocalDeclared
	object.ThanosRulerListenLocalValid = summary.ListenLocalValid
	object.ThanosRulerLogLevel = summary.LogLevel
	object.ThanosRulerLogLevelDeclared = summary.LogLevelDeclared
	object.ThanosRulerLogLevelValid = summary.LogLevelValid
	object.ThanosRulerLogFormat = summary.LogFormat
	object.ThanosRulerLogFormatDeclared = summary.LogFormatDeclared
	object.ThanosRulerLogFormatValid = summary.LogFormatValid
	object.ThanosRulerContainersDeclared = summary.ContainersDeclared
	object.ThanosRulerSidecarContainerCount = summary.SidecarContainerCount
	object.ThanosRulerContainerInvalidCount = summary.ContainerInvalidCount
	object.ThanosRulerInitContainersDeclared = summary.InitContainersDeclared
	object.ThanosRulerInitContainerInvalidCount = summary.InitContainerInvalidCount
	object.ThanosRulerManagedContainerOverrideCount = summary.ManagedContainerOverrideCount
	object.ThanosRulerManagedInitContainerOverrideCount = summary.ManagedInitContainerOverrideCount
}

func populateKubernetesThanosRulerRuntimeMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_runtime_metadata"] = strconv.FormatBool(object.ThanosRulerRuntimeMetadata)
	resource.Metadata["thanos_ruler_listen_local_declared"] = strconv.FormatBool(object.ThanosRulerListenLocalDeclared)
	resource.Metadata["thanos_ruler_listen_local_valid"] = strconv.FormatBool(object.ThanosRulerListenLocalValid)
	resource.Metadata["thanos_ruler_listen_local_enabled"] = strconv.FormatBool(object.ThanosRulerListenLocalEnabled)
	resource.Metadata["thanos_ruler_log_level_declared"] = strconv.FormatBool(object.ThanosRulerLogLevelDeclared)
	resource.Metadata["thanos_ruler_log_level_valid"] = strconv.FormatBool(object.ThanosRulerLogLevelValid)
	resource.Metadata["thanos_ruler_log_level"] = object.ThanosRulerLogLevel
	resource.Metadata["thanos_ruler_log_format_declared"] = strconv.FormatBool(object.ThanosRulerLogFormatDeclared)
	resource.Metadata["thanos_ruler_log_format_valid"] = strconv.FormatBool(object.ThanosRulerLogFormatValid)
	resource.Metadata["thanos_ruler_log_format"] = object.ThanosRulerLogFormat
	resource.Metadata["thanos_ruler_containers_declared"] = strconv.FormatBool(object.ThanosRulerContainersDeclared)
	resource.Metadata["thanos_ruler_sidecar_container_count"] = strconv.Itoa(object.ThanosRulerSidecarContainerCount)
	resource.Metadata["thanos_ruler_container_invalid_count"] = strconv.Itoa(object.ThanosRulerContainerInvalidCount)
	resource.Metadata["thanos_ruler_init_containers_declared"] = strconv.FormatBool(object.ThanosRulerInitContainersDeclared)
	resource.Metadata["thanos_ruler_init_container_invalid_count"] = strconv.Itoa(object.ThanosRulerInitContainerInvalidCount)
	resource.Metadata["thanos_ruler_managed_container_override_count"] = strconv.Itoa(object.ThanosRulerManagedContainerOverrideCount)
	resource.Metadata["thanos_ruler_managed_init_container_override_count"] = strconv.Itoa(object.ThanosRulerManagedInitContainerOverrideCount)
}
