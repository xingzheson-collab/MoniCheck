package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerTerminationObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesTerminationGrace(spec)
	object.ThanosRulerTerminationGraceDeclared = summary.Declared
	object.ThanosRulerTerminationGraceValid = summary.Valid
	object.ThanosRulerTerminationGraceSeconds = summary.Seconds
}

func populateKubernetesThanosRulerTerminationMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_termination_grace_declared"] = strconv.FormatBool(object.ThanosRulerTerminationGraceDeclared)
	resource.Metadata["thanos_ruler_termination_grace_valid"] = strconv.FormatBool(object.ThanosRulerTerminationGraceValid)
	resource.Metadata["thanos_ruler_termination_grace_seconds"] = strconv.FormatInt(object.ThanosRulerTerminationGraceSeconds, 10)
}
