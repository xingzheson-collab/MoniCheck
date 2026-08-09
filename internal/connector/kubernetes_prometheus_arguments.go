package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusArgumentsObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesArguments(spec)
	object.PrometheusArgumentMetadata = true
	object.PrometheusFeatureDeclared = summary.FeatureDeclared
	object.PrometheusFeatureCount = summary.FeatureCount
	object.PrometheusFeatureInvalidCount = summary.FeatureInvalidCount
	object.PrometheusFeatureDuplicateCount = summary.FeatureDuplicateCount
	object.PrometheusAdditionalArgsDeclared = summary.AdditionalArgsDeclared
	object.PrometheusAdditionalArgCount = summary.AdditionalArgCount
	object.PrometheusAdditionalArgInvalidCount = summary.AdditionalArgInvalidCount
	object.PrometheusAdditionalArgDuplicateCount = summary.AdditionalArgDuplicateCount
}

func populateKubernetesPrometheusArgumentsMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_argument_metadata"] = strconv.FormatBool(object.PrometheusArgumentMetadata)
	resource.Metadata["prometheus_feature_declared"] = strconv.FormatBool(object.PrometheusFeatureDeclared)
	resource.Metadata["prometheus_feature_count"] = strconv.Itoa(object.PrometheusFeatureCount)
	resource.Metadata["prometheus_feature_invalid_count"] = strconv.Itoa(object.PrometheusFeatureInvalidCount)
	resource.Metadata["prometheus_feature_duplicate_count"] = strconv.Itoa(object.PrometheusFeatureDuplicateCount)
	resource.Metadata["prometheus_additional_args_declared"] = strconv.FormatBool(object.PrometheusAdditionalArgsDeclared)
	resource.Metadata["prometheus_additional_arg_count"] = strconv.Itoa(object.PrometheusAdditionalArgCount)
	resource.Metadata["prometheus_additional_arg_invalid_count"] = strconv.Itoa(object.PrometheusAdditionalArgInvalidCount)
	resource.Metadata["prometheus_additional_arg_duplicate_count"] = strconv.Itoa(object.PrometheusAdditionalArgDuplicateCount)
}
