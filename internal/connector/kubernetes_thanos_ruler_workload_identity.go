package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerWorkloadIdentityObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerWorkloadIdentityMetadata = true
	serviceName := yamlMappingValue(spec, "serviceName")
	object.ThanosRulerServiceNameDeclared = yamlValueDeclared(serviceName)
	if object.ThanosRulerServiceNameDeclared && serviceName.Kind == yaml.ScalarNode {
		name := strings.TrimSpace(serviceName.Value)
		object.ThanosRulerServiceNameConfigured = name != ""
		object.ThanosRulerServiceNameValid = object.ThanosRulerServiceNameConfigured && len(validation.IsDNS1123Subdomain(name)) == 0
		if object.ThanosRulerServiceNameValid {
			object.ThanosRulerServiceName = name
		}
	}

	serviceAccount := yamlMappingValue(spec, "serviceAccountName")
	object.ThanosRulerServiceAccountNameDeclared = yamlValueDeclared(serviceAccount)
	if object.ThanosRulerServiceAccountNameDeclared && serviceAccount.Kind == yaml.ScalarNode {
		name := strings.TrimSpace(serviceAccount.Value)
		object.ThanosRulerServiceAccountNameValid = name != "" && len(validation.IsDNS1123Subdomain(name)) == 0
		object.ThanosRulerCustomServiceAccount = object.ThanosRulerServiceAccountNameValid && name != "default"
	}
}

func populateKubernetesThanosRulerWorkloadIdentityMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_workload_identity_metadata"] = strconv.FormatBool(object.ThanosRulerWorkloadIdentityMetadata)
	resource.Metadata["thanos_ruler_service_name_declared"] = strconv.FormatBool(object.ThanosRulerServiceNameDeclared)
	resource.Metadata["thanos_ruler_service_name_configured"] = strconv.FormatBool(object.ThanosRulerServiceNameConfigured)
	resource.Metadata["thanos_ruler_service_name_valid"] = strconv.FormatBool(object.ThanosRulerServiceNameValid)
	resource.Metadata["thanos_ruler_shared_service_count"] = strconv.Itoa(object.ThanosRulerSharedServiceCount)
	resource.Metadata["thanos_ruler_service_account_name_declared"] = strconv.FormatBool(object.ThanosRulerServiceAccountNameDeclared)
	resource.Metadata["thanos_ruler_service_account_name_valid"] = strconv.FormatBool(object.ThanosRulerServiceAccountNameValid)
	resource.Metadata["thanos_ruler_custom_service_account"] = strconv.FormatBool(object.ThanosRulerCustomServiceAccount)
}

func populateKubernetesThanosRulerWorkloadIdentityTopology(resources map[string]model.Resource, rulers []kubernetesPrometheusResource) {
	serviceUsers := map[string]int{}
	for _, ruler := range rulers {
		serviceName := ruler.Object.ThanosRulerServiceName
		if serviceName == "" {
			serviceName = "thanos-ruler-operated"
		}
		serviceUsers[ruler.Object.Namespace+"\x00"+serviceName]++
	}
	for _, ruler := range rulers {
		serviceName := ruler.Object.ThanosRulerServiceName
		if serviceName == "" {
			serviceName = "thanos-ruler-operated"
		}
		resource := resources[ruler.Resource.ID]
		resource.Metadata["thanos_ruler_shared_service_count"] = strconv.Itoa(serviceUsers[ruler.Object.Namespace+"\x00"+serviceName] - 1)
		resources[resource.ID] = resource
	}
}
