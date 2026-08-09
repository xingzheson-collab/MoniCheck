package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesPrometheusSecurityObject(object *kubernetesObject, spec *yaml.Node) {
	object.PrometheusAutomountTokenEnabled, object.PrometheusAutomountTokenDeclared, object.PrometheusAutomountTokenValid = parseKubernetesBooleanSetting(yamlMappingValue(spec, "automountServiceAccountToken"))
}

func populateKubernetesPrometheusSecurityMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_automount_token_declared"] = strconv.FormatBool(object.PrometheusAutomountTokenDeclared)
	resource.Metadata["prometheus_automount_token_valid"] = strconv.FormatBool(object.PrometheusAutomountTokenValid)
	resource.Metadata["prometheus_automount_token_enabled"] = strconv.FormatBool(object.PrometheusAutomountTokenEnabled)
}
