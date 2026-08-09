package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerResourceObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesResourceRequirementsSummary(spec)
	object.AlertmanagerResourceMetadata = true
	object.AlertmanagerResourcesDeclared = summary.Declared
	object.AlertmanagerResourcesObjectValid = summary.ObjectValid
	object.AlertmanagerResourceInvalidSettingCount = summary.InvalidCount
	object.AlertmanagerCPURequestDeclared, object.AlertmanagerCPURequestValid, object.AlertmanagerCPURequestPositive = summary.CPURequest.declared, summary.CPURequest.valid, summary.CPURequest.positive
	object.AlertmanagerMemoryRequestDeclared, object.AlertmanagerMemoryRequestValid, object.AlertmanagerMemoryRequestPositive = summary.MemoryRequest.declared, summary.MemoryRequest.valid, summary.MemoryRequest.positive
	object.AlertmanagerCPULimitDeclared, object.AlertmanagerCPULimitValid, object.AlertmanagerCPULimitPositive = summary.CPULimit.declared, summary.CPULimit.valid, summary.CPULimit.positive
	object.AlertmanagerMemoryLimitDeclared, object.AlertmanagerMemoryLimitValid, object.AlertmanagerMemoryLimitPositive = summary.MemoryLimit.declared, summary.MemoryLimit.valid, summary.MemoryLimit.positive
}

func populateKubernetesAlertmanagerResourceMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_resource_metadata"] = strconv.FormatBool(object.AlertmanagerResourceMetadata)
	resource.Metadata["alertmanager_resources_declared"] = strconv.FormatBool(object.AlertmanagerResourcesDeclared)
	resource.Metadata["alertmanager_resources_object_valid"] = strconv.FormatBool(object.AlertmanagerResourcesObjectValid)
	resource.Metadata["alertmanager_resource_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerResourceInvalidSettingCount)
	resource.Metadata["alertmanager_cpu_request_declared"] = strconv.FormatBool(object.AlertmanagerCPURequestDeclared)
	resource.Metadata["alertmanager_cpu_request_valid"] = strconv.FormatBool(object.AlertmanagerCPURequestValid)
	resource.Metadata["alertmanager_cpu_request_positive"] = strconv.FormatBool(object.AlertmanagerCPURequestPositive)
	resource.Metadata["alertmanager_memory_request_declared"] = strconv.FormatBool(object.AlertmanagerMemoryRequestDeclared)
	resource.Metadata["alertmanager_memory_request_valid"] = strconv.FormatBool(object.AlertmanagerMemoryRequestValid)
	resource.Metadata["alertmanager_memory_request_positive"] = strconv.FormatBool(object.AlertmanagerMemoryRequestPositive)
	resource.Metadata["alertmanager_cpu_limit_declared"] = strconv.FormatBool(object.AlertmanagerCPULimitDeclared)
	resource.Metadata["alertmanager_cpu_limit_valid"] = strconv.FormatBool(object.AlertmanagerCPULimitValid)
	resource.Metadata["alertmanager_cpu_limit_positive"] = strconv.FormatBool(object.AlertmanagerCPULimitPositive)
	resource.Metadata["alertmanager_memory_limit_declared"] = strconv.FormatBool(object.AlertmanagerMemoryLimitDeclared)
	resource.Metadata["alertmanager_memory_limit_valid"] = strconv.FormatBool(object.AlertmanagerMemoryLimitValid)
	resource.Metadata["alertmanager_memory_limit_positive"] = strconv.FormatBool(object.AlertmanagerMemoryLimitPositive)
}
