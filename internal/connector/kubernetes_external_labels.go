package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusExternalLabelObject(object *kubernetesObject, spec *yaml.Node) {
	replicaNode := yamlMappingValue(spec, "replicaExternalLabelName")
	object.PrometheusReplicaExternalDeclared = yamlValueDeclared(replicaNode)
	object.PrometheusReplicaExternalEnabled = !object.PrometheusReplicaExternalDeclared || yamlScalarValue(replicaNode) != ""
	instanceNode := yamlMappingValue(spec, "prometheusExternalLabelName")
	object.PrometheusInstanceExternalDeclared = yamlValueDeclared(instanceNode)
	object.PrometheusInstanceExternalEnabled = !object.PrometheusInstanceExternalDeclared || yamlScalarValue(instanceNode) != ""
	externalLabels := yamlMappingValue(spec, "externalLabels")
	if externalLabels != nil && externalLabels.Kind == yaml.MappingNode {
		object.PrometheusExternalLabelCount = len(externalLabels.Content) / 2
	}
}

func populateKubernetesPrometheusExternalLabelMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_replica_external_label_declared"] = strconv.FormatBool(object.PrometheusReplicaExternalDeclared)
	resource.Metadata["prometheus_replica_external_label_enabled"] = strconv.FormatBool(object.PrometheusReplicaExternalEnabled)
	resource.Metadata["prometheus_instance_external_label_declared"] = strconv.FormatBool(object.PrometheusInstanceExternalDeclared)
	resource.Metadata["prometheus_instance_external_label_enabled"] = strconv.FormatBool(object.PrometheusInstanceExternalEnabled)
	resource.Metadata["prometheus_external_label_count"] = strconv.Itoa(object.PrometheusExternalLabelCount)
}
