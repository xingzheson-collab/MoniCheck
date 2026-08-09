package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesPrometheusPodSecurityObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPodSecuritySummary(spec)
	object.PrometheusPodSecurityMetadata = true
	object.PrometheusSecurityContextInvalidCount = summary.InvalidCount
	object.PrometheusRootUserContextCount = summary.RootUserCount
	object.PrometheusNonRootDisabledContextCount = summary.NonRootDisabledCount
	object.PrometheusPrivilegedContainerCount = summary.PrivilegedCount
	object.PrometheusHostProcessContextCount = summary.HostProcessCount
	object.PrometheusPrivilegeEscalationContextCount = summary.PrivilegeEscalationCount
	object.PrometheusUnconfinedSeccompContextCount = summary.UnconfinedSeccompCount
	object.PrometheusCapabilityAdditionContextCount = summary.CapabilityAdditionCount
	object.PrometheusWritableRootFilesystemContextCount = summary.WritableRootFSCount
}

func populateKubernetesPrometheusPodSecurityMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_pod_security_metadata"] = strconv.FormatBool(object.PrometheusPodSecurityMetadata)
	resource.Metadata["prometheus_security_context_invalid_count"] = strconv.Itoa(object.PrometheusSecurityContextInvalidCount)
	resource.Metadata["prometheus_root_user_context_count"] = strconv.Itoa(object.PrometheusRootUserContextCount)
	resource.Metadata["prometheus_non_root_disabled_context_count"] = strconv.Itoa(object.PrometheusNonRootDisabledContextCount)
	resource.Metadata["prometheus_privileged_container_count"] = strconv.Itoa(object.PrometheusPrivilegedContainerCount)
	resource.Metadata["prometheus_host_process_context_count"] = strconv.Itoa(object.PrometheusHostProcessContextCount)
	resource.Metadata["prometheus_privilege_escalation_context_count"] = strconv.Itoa(object.PrometheusPrivilegeEscalationContextCount)
	resource.Metadata["prometheus_unconfined_seccomp_context_count"] = strconv.Itoa(object.PrometheusUnconfinedSeccompContextCount)
	resource.Metadata["prometheus_capability_addition_context_count"] = strconv.Itoa(object.PrometheusCapabilityAdditionContextCount)
	resource.Metadata["prometheus_writable_root_filesystem_context_count"] = strconv.Itoa(object.PrometheusWritableRootFilesystemContextCount)
}
