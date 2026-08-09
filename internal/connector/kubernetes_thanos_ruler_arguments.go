package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerArgumentsObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesArguments(spec)
	object.ThanosRulerArgumentMetadata = true
	object.ThanosRulerFeatureDeclared = summary.FeatureDeclared
	object.ThanosRulerFeatureCount = summary.FeatureCount
	object.ThanosRulerFeatureInvalidCount = summary.FeatureInvalidCount
	object.ThanosRulerFeatureDuplicateCount = summary.FeatureDuplicateCount
	featureSupported, featureEvaluable := kubernetesPrometheusVersionAtLeast(object.PrometheusVersion, 0, 39)
	object.ThanosRulerFeatureVersionEvaluable = featureEvaluable
	object.ThanosRulerFeatureVersionUnsupported = object.ThanosRulerFeatureCount > 0 && featureEvaluable && !featureSupported
	object.ThanosRulerAdditionalArgsDeclared = summary.AdditionalArgsDeclared
	object.ThanosRulerAdditionalArgCount = summary.AdditionalArgCount
	object.ThanosRulerAdditionalArgInvalidCount = summary.AdditionalArgInvalidCount
	object.ThanosRulerAdditionalArgDuplicateCount = summary.AdditionalArgDuplicateCount
}

func populateKubernetesThanosRulerArgumentsMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_argument_metadata"] = strconv.FormatBool(object.ThanosRulerArgumentMetadata)
	resource.Metadata["thanos_ruler_feature_declared"] = strconv.FormatBool(object.ThanosRulerFeatureDeclared)
	resource.Metadata["thanos_ruler_feature_count"] = strconv.Itoa(object.ThanosRulerFeatureCount)
	resource.Metadata["thanos_ruler_feature_invalid_count"] = strconv.Itoa(object.ThanosRulerFeatureInvalidCount)
	resource.Metadata["thanos_ruler_feature_duplicate_count"] = strconv.Itoa(object.ThanosRulerFeatureDuplicateCount)
	resource.Metadata["thanos_ruler_feature_version_evaluable"] = strconv.FormatBool(object.ThanosRulerFeatureVersionEvaluable)
	resource.Metadata["thanos_ruler_feature_version_unsupported"] = strconv.FormatBool(object.ThanosRulerFeatureVersionUnsupported)
	resource.Metadata["thanos_ruler_additional_args_declared"] = strconv.FormatBool(object.ThanosRulerAdditionalArgsDeclared)
	resource.Metadata["thanos_ruler_additional_arg_count"] = strconv.Itoa(object.ThanosRulerAdditionalArgCount)
	resource.Metadata["thanos_ruler_additional_arg_invalid_count"] = strconv.Itoa(object.ThanosRulerAdditionalArgInvalidCount)
	resource.Metadata["thanos_ruler_additional_arg_duplicate_count"] = strconv.Itoa(object.ThanosRulerAdditionalArgDuplicateCount)
}
