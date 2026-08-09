package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerResourceObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesResourceRequirementsSummary(spec)
	object.ThanosRulerResourceMetadata = true
	object.ThanosRulerResourcesDeclared = summary.Declared
	object.ThanosRulerResourcesObjectValid = summary.ObjectValid
	object.ThanosRulerResourceInvalidSettingCount = summary.InvalidCount
	object.ThanosRulerCPURequestDeclared, object.ThanosRulerCPURequestValid, object.ThanosRulerCPURequestPositive = summary.CPURequest.declared, summary.CPURequest.valid, summary.CPURequest.positive
	object.ThanosRulerMemoryRequestDeclared, object.ThanosRulerMemoryRequestValid, object.ThanosRulerMemoryRequestPositive = summary.MemoryRequest.declared, summary.MemoryRequest.valid, summary.MemoryRequest.positive
	object.ThanosRulerCPULimitDeclared, object.ThanosRulerCPULimitValid, object.ThanosRulerCPULimitPositive = summary.CPULimit.declared, summary.CPULimit.valid, summary.CPULimit.positive
	object.ThanosRulerMemoryLimitDeclared, object.ThanosRulerMemoryLimitValid, object.ThanosRulerMemoryLimitPositive = summary.MemoryLimit.declared, summary.MemoryLimit.valid, summary.MemoryLimit.positive
}

func populateKubernetesThanosRulerResourceMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_resource_metadata"] = strconv.FormatBool(object.ThanosRulerResourceMetadata)
	resource.Metadata["thanos_ruler_resources_declared"] = strconv.FormatBool(object.ThanosRulerResourcesDeclared)
	resource.Metadata["thanos_ruler_resources_object_valid"] = strconv.FormatBool(object.ThanosRulerResourcesObjectValid)
	resource.Metadata["thanos_ruler_resource_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerResourceInvalidSettingCount)
	resource.Metadata["thanos_ruler_cpu_request_declared"] = strconv.FormatBool(object.ThanosRulerCPURequestDeclared)
	resource.Metadata["thanos_ruler_cpu_request_valid"] = strconv.FormatBool(object.ThanosRulerCPURequestValid)
	resource.Metadata["thanos_ruler_cpu_request_positive"] = strconv.FormatBool(object.ThanosRulerCPURequestPositive)
	resource.Metadata["thanos_ruler_memory_request_declared"] = strconv.FormatBool(object.ThanosRulerMemoryRequestDeclared)
	resource.Metadata["thanos_ruler_memory_request_valid"] = strconv.FormatBool(object.ThanosRulerMemoryRequestValid)
	resource.Metadata["thanos_ruler_memory_request_positive"] = strconv.FormatBool(object.ThanosRulerMemoryRequestPositive)
	resource.Metadata["thanos_ruler_cpu_limit_declared"] = strconv.FormatBool(object.ThanosRulerCPULimitDeclared)
	resource.Metadata["thanos_ruler_cpu_limit_valid"] = strconv.FormatBool(object.ThanosRulerCPULimitValid)
	resource.Metadata["thanos_ruler_cpu_limit_positive"] = strconv.FormatBool(object.ThanosRulerCPULimitPositive)
	resource.Metadata["thanos_ruler_memory_limit_declared"] = strconv.FormatBool(object.ThanosRulerMemoryLimitDeclared)
	resource.Metadata["thanos_ruler_memory_limit_valid"] = strconv.FormatBool(object.ThanosRulerMemoryLimitValid)
	resource.Metadata["thanos_ruler_memory_limit_positive"] = strconv.FormatBool(object.ThanosRulerMemoryLimitPositive)
}
