package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerArgumentsObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesArguments(spec)
	object.AlertmanagerArgumentMetadata = true
	object.AlertmanagerFeatureDeclared = summary.FeatureDeclared
	object.AlertmanagerFeatureCount = summary.FeatureCount
	object.AlertmanagerFeatureInvalidCount = summary.FeatureInvalidCount
	object.AlertmanagerFeatureDuplicateCount = summary.FeatureDuplicateCount
	featureSupported, featureEvaluable := kubernetesPrometheusVersionAtLeast(object.AlertmanagerVersion, 0, 27)
	object.AlertmanagerFeatureVersionEvaluable = featureEvaluable
	object.AlertmanagerFeatureVersionUnsupported = object.AlertmanagerFeatureCount > 0 && featureEvaluable && !featureSupported

	object.AlertmanagerAdditionalArgsDeclared = summary.AdditionalArgsDeclared
	object.AlertmanagerAdditionalArgCount = summary.AdditionalArgCount
	object.AlertmanagerAdditionalArgInvalidCount = summary.AdditionalArgInvalidCount
	object.AlertmanagerAdditionalArgDuplicateCount = summary.AdditionalArgDuplicateCount
	argsSupported, argsEvaluable := kubernetesPrometheusVersionAtLeast(object.AlertmanagerVersion, 0, 25)
	object.AlertmanagerAdditionalArgsVersionEvaluable = argsEvaluable
	object.AlertmanagerAdditionalArgsVersionUnsupported = object.AlertmanagerAdditionalArgCount > 0 && argsEvaluable && !argsSupported
}

func populateKubernetesAlertmanagerArgumentsMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_argument_metadata"] = strconv.FormatBool(object.AlertmanagerArgumentMetadata)
	resource.Metadata["alertmanager_feature_declared"] = strconv.FormatBool(object.AlertmanagerFeatureDeclared)
	resource.Metadata["alertmanager_feature_count"] = strconv.Itoa(object.AlertmanagerFeatureCount)
	resource.Metadata["alertmanager_feature_invalid_count"] = strconv.Itoa(object.AlertmanagerFeatureInvalidCount)
	resource.Metadata["alertmanager_feature_duplicate_count"] = strconv.Itoa(object.AlertmanagerFeatureDuplicateCount)
	resource.Metadata["alertmanager_feature_version_evaluable"] = strconv.FormatBool(object.AlertmanagerFeatureVersionEvaluable)
	resource.Metadata["alertmanager_feature_version_unsupported"] = strconv.FormatBool(object.AlertmanagerFeatureVersionUnsupported)
	resource.Metadata["alertmanager_additional_args_declared"] = strconv.FormatBool(object.AlertmanagerAdditionalArgsDeclared)
	resource.Metadata["alertmanager_additional_arg_count"] = strconv.Itoa(object.AlertmanagerAdditionalArgCount)
	resource.Metadata["alertmanager_additional_arg_invalid_count"] = strconv.Itoa(object.AlertmanagerAdditionalArgInvalidCount)
	resource.Metadata["alertmanager_additional_arg_duplicate_count"] = strconv.Itoa(object.AlertmanagerAdditionalArgDuplicateCount)
	resource.Metadata["alertmanager_additional_args_version_evaluable"] = strconv.FormatBool(object.AlertmanagerAdditionalArgsVersionEvaluable)
	resource.Metadata["alertmanager_additional_args_version_unsupported"] = strconv.FormatBool(object.AlertmanagerAdditionalArgsVersionUnsupported)
}
