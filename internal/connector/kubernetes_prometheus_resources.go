package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusResourceObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesResourceRequirementsSummary(spec)
	object.PrometheusResourceMetadata = true
	object.PrometheusResourcesDeclared = summary.Declared
	object.PrometheusResourcesObjectValid = summary.ObjectValid
	object.PrometheusResourceInvalidSettingCount = summary.InvalidCount
	object.PrometheusCPURequestDeclared, object.PrometheusCPURequestValid, object.PrometheusCPURequestPositive = summary.CPURequest.declared, summary.CPURequest.valid, summary.CPURequest.positive
	object.PrometheusMemoryRequestDeclared, object.PrometheusMemoryRequestValid, object.PrometheusMemoryRequestPositive = summary.MemoryRequest.declared, summary.MemoryRequest.valid, summary.MemoryRequest.positive
	object.PrometheusCPULimitDeclared, object.PrometheusCPULimitValid, object.PrometheusCPULimitPositive = summary.CPULimit.declared, summary.CPULimit.valid, summary.CPULimit.positive
	object.PrometheusMemoryLimitDeclared, object.PrometheusMemoryLimitValid, object.PrometheusMemoryLimitPositive = summary.MemoryLimit.declared, summary.MemoryLimit.valid, summary.MemoryLimit.positive
}

func populateKubernetesPrometheusResourceMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_resource_metadata"] = strconv.FormatBool(object.PrometheusResourceMetadata)
	resource.Metadata["prometheus_resources_declared"] = strconv.FormatBool(object.PrometheusResourcesDeclared)
	resource.Metadata["prometheus_resources_object_valid"] = strconv.FormatBool(object.PrometheusResourcesObjectValid)
	resource.Metadata["prometheus_resource_invalid_setting_count"] = strconv.Itoa(object.PrometheusResourceInvalidSettingCount)
	resource.Metadata["prometheus_cpu_request_declared"] = strconv.FormatBool(object.PrometheusCPURequestDeclared)
	resource.Metadata["prometheus_cpu_request_valid"] = strconv.FormatBool(object.PrometheusCPURequestValid)
	resource.Metadata["prometheus_cpu_request_positive"] = strconv.FormatBool(object.PrometheusCPURequestPositive)
	resource.Metadata["prometheus_memory_request_declared"] = strconv.FormatBool(object.PrometheusMemoryRequestDeclared)
	resource.Metadata["prometheus_memory_request_valid"] = strconv.FormatBool(object.PrometheusMemoryRequestValid)
	resource.Metadata["prometheus_memory_request_positive"] = strconv.FormatBool(object.PrometheusMemoryRequestPositive)
	resource.Metadata["prometheus_cpu_limit_declared"] = strconv.FormatBool(object.PrometheusCPULimitDeclared)
	resource.Metadata["prometheus_cpu_limit_valid"] = strconv.FormatBool(object.PrometheusCPULimitValid)
	resource.Metadata["prometheus_cpu_limit_positive"] = strconv.FormatBool(object.PrometheusCPULimitPositive)
	resource.Metadata["prometheus_memory_limit_declared"] = strconv.FormatBool(object.PrometheusMemoryLimitDeclared)
	resource.Metadata["prometheus_memory_limit_valid"] = strconv.FormatBool(object.PrometheusMemoryLimitValid)
	resource.Metadata["prometheus_memory_limit_positive"] = strconv.FormatBool(object.PrometheusMemoryLimitPositive)
}
