package connector

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	prommodel "github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

var storageQuantityPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([KMGTPE]i?|B|KB|MB|GB|TB|PB|EB)?$`)

func populateKubernetesPrometheusStorageObject(object *kubernetesObject, spec *yaml.Node) {
	storage := yamlMappingValue(spec, "storage")
	object.PrometheusStorageDeclared = yamlValueDeclared(storage)
	emptyDirDeclared := yamlValueDeclared(yamlMappingValue(storage, "emptyDir"))
	ephemeralDeclared := yamlValueDeclared(yamlMappingValue(storage, "ephemeral"))
	pvc := yamlMappingValue(storage, "volumeClaimTemplate")
	pvcDeclared := yamlValueDeclared(pvc)
	for _, declared := range []bool{emptyDirDeclared, ephemeralDeclared, pvcDeclared} {
		if declared {
			object.PrometheusStorageOptionCount++
		}
	}
	switch {
	case emptyDirDeclared:
		object.PrometheusStorageMode = "empty-dir"
	case ephemeralDeclared:
		object.PrometheusStorageMode = "ephemeral"
	case pvcDeclared:
		object.PrometheusStorageMode = "pvc"
	default:
		object.PrometheusStorageMode = "default-empty-dir"
	}
	pvcRequest := yamlScalarValue(yamlMappingValue(yamlMappingValue(yamlMappingValue(yamlMappingValue(pvc, "spec"), "resources"), "requests"), "storage"))
	object.PrometheusPVCRequestDeclared = pvcRequest != ""
	object.PrometheusPVCRequestBytes, object.PrometheusPVCRequestValid = parseKubernetesStorageQuantity(pvcRequest)
	pvcRetention := parseKubernetesPVCRetentionPolicy(yamlMappingValue(spec, "persistentVolumeClaimRetentionPolicy"))
	object.PrometheusPVCRetentionApplicable = object.Kind == "Prometheus" || object.PrometheusAgentMode != "daemonset"
	object.PrometheusPVCRetentionPolicyDeclared = pvcRetention.Declared
	object.PrometheusPVCRetentionPolicyObjectValid = pvcRetention.ObjectValid
	object.PrometheusPVCWhenDeletedValid = pvcRetention.WhenDeletedValid
	object.PrometheusPVCWhenDeleted = pvcRetention.WhenDeleted
	object.PrometheusPVCWhenScaledValid = pvcRetention.WhenScaledValid
	object.PrometheusPVCWhenScaled = pvcRetention.WhenScaled
	object.PrometheusPVCRetentionInvalidSettingCount = pvcRetention.InvalidSettingCount
	if pvcRetention.Declared && !object.PrometheusPVCRetentionApplicable {
		object.PrometheusPVCRetentionInvalidSettingCount++
	}
	termination := parseKubernetesTerminationGrace(spec)
	object.PrometheusTerminationGraceDeclared = termination.Declared
	object.PrometheusTerminationGraceValid = termination.Valid
	object.PrometheusTerminationGraceSeconds = termination.Seconds

	walNode := yamlMappingValue(spec, "walCompression")
	object.PrometheusWALCompressionEnabled, object.PrometheusWALCompressionDeclared = yamlBoolValueWithDefault(walNode, true)
	if object.Kind != "Prometheus" {
		return
	}
	object.PrometheusDisableCompaction = yamlBoolValue(yamlMappingValue(spec, "disableCompaction"))
	thanos := yamlMappingValue(spec, "thanos")
	object.PrometheusThanosObjectStorage = yamlValueDeclared(yamlMappingValue(thanos, "objectStorageConfig")) || yamlScalarValue(yamlMappingValue(thanos, "objectStorageConfigFile")) != ""
	retention := yamlScalarValue(yamlMappingValue(spec, "retention"))
	object.PrometheusRetentionDeclared = retention != ""
	object.PrometheusRetentionSeconds, object.PrometheusRetentionValid = parsePrometheusRetentionDuration(retention)
	retentionSize := yamlScalarValue(yamlMappingValue(spec, "retentionSize"))
	object.PrometheusRetentionSizeDeclared = retentionSize != ""
	object.PrometheusRetentionSizeBytes, object.PrometheusRetentionSizeValid = parsePrometheusByteSize(retentionSize)
}

func populateKubernetesPrometheusStorageMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_storage_declared"] = strconv.FormatBool(object.PrometheusStorageDeclared)
	resource.Metadata["prometheus_storage_mode"] = object.PrometheusStorageMode
	resource.Metadata["prometheus_storage_option_count"] = strconv.Itoa(object.PrometheusStorageOptionCount)
	resource.Metadata["prometheus_pvc_request_declared"] = strconv.FormatBool(object.PrometheusPVCRequestDeclared)
	resource.Metadata["prometheus_pvc_request_valid"] = strconv.FormatBool(object.PrometheusPVCRequestValid)
	resource.Metadata["prometheus_pvc_request_bytes"] = strconv.FormatInt(object.PrometheusPVCRequestBytes, 10)
	resource.Metadata["prometheus_pvc_retention_applicable"] = strconv.FormatBool(object.PrometheusPVCRetentionApplicable)
	resource.Metadata["prometheus_pvc_retention_policy_declared"] = strconv.FormatBool(object.PrometheusPVCRetentionPolicyDeclared)
	resource.Metadata["prometheus_pvc_retention_policy_object_valid"] = strconv.FormatBool(object.PrometheusPVCRetentionPolicyObjectValid)
	resource.Metadata["prometheus_pvc_when_deleted_valid"] = strconv.FormatBool(object.PrometheusPVCWhenDeletedValid)
	resource.Metadata["prometheus_pvc_when_deleted"] = object.PrometheusPVCWhenDeleted
	resource.Metadata["prometheus_pvc_when_scaled_valid"] = strconv.FormatBool(object.PrometheusPVCWhenScaledValid)
	resource.Metadata["prometheus_pvc_when_scaled"] = object.PrometheusPVCWhenScaled
	resource.Metadata["prometheus_pvc_retention_invalid_setting_count"] = strconv.Itoa(object.PrometheusPVCRetentionInvalidSettingCount)
	resource.Metadata["prometheus_termination_grace_declared"] = strconv.FormatBool(object.PrometheusTerminationGraceDeclared)
	resource.Metadata["prometheus_termination_grace_valid"] = strconv.FormatBool(object.PrometheusTerminationGraceValid)
	resource.Metadata["prometheus_termination_grace_seconds"] = strconv.FormatInt(object.PrometheusTerminationGraceSeconds, 10)
	resource.Metadata["prometheus_retention_declared"] = strconv.FormatBool(object.PrometheusRetentionDeclared)
	resource.Metadata["prometheus_retention_valid"] = strconv.FormatBool(object.PrometheusRetentionValid)
	resource.Metadata["prometheus_retention_seconds"] = strconv.FormatInt(object.PrometheusRetentionSeconds, 10)
	resource.Metadata["prometheus_retention_size_declared"] = strconv.FormatBool(object.PrometheusRetentionSizeDeclared)
	resource.Metadata["prometheus_retention_size_valid"] = strconv.FormatBool(object.PrometheusRetentionSizeValid)
	resource.Metadata["prometheus_retention_size_bytes"] = strconv.FormatInt(object.PrometheusRetentionSizeBytes, 10)
	retentionExceedsPVC := object.PrometheusStorageMode == "pvc" && object.PrometheusRetentionSizeValid && object.PrometheusPVCRequestValid && object.PrometheusRetentionSizeBytes >= object.PrometheusPVCRequestBytes
	resource.Metadata["prometheus_retention_exceeds_pvc"] = strconv.FormatBool(retentionExceedsPVC)
	resource.Metadata["prometheus_wal_compression_declared"] = strconv.FormatBool(object.PrometheusWALCompressionDeclared)
	resource.Metadata["prometheus_wal_compression_enabled"] = strconv.FormatBool(object.PrometheusWALCompressionEnabled)
	resource.Metadata["prometheus_disable_compaction"] = strconv.FormatBool(object.PrometheusDisableCompaction)
	resource.Metadata["prometheus_thanos_object_storage_declared"] = strconv.FormatBool(object.PrometheusThanosObjectStorage)
}

func parsePrometheusRetentionDuration(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parsed, err := prommodel.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	seconds := float64(time.Duration(parsed)) / float64(time.Second)
	if seconds > math.MaxInt64 {
		return 0, false
	}
	return int64(seconds), true
}

func parsePrometheusByteSize(value string) (int64, bool) {
	return parseStorageQuantity(value, true)
}

func parseKubernetesStorageQuantity(value string) (int64, bool) {
	return parseStorageQuantity(value, false)
}

func parseStorageQuantity(value string, prometheusByteUnits bool) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	matches := storageQuantityPattern.FindStringSubmatch(value)
	if len(matches) != 3 {
		return 0, false
	}
	number, err := strconv.ParseFloat(matches[1], 64)
	if err != nil || number <= 0 {
		return 0, false
	}
	unit := matches[2]
	power := 0
	if unit != "" && unit != "B" {
		prefix := unit[0]
		power = strings.IndexByte("KMGTPE", prefix) + 1
		if power == 0 {
			return 0, false
		}
	}
	base := float64(1000)
	if prometheusByteUnits || strings.HasSuffix(unit, "i") || strings.HasSuffix(unit, "B") {
		base = 1024
	}
	bytes := number * math.Pow(base, float64(power))
	if bytes > math.MaxInt64 || bytes < 1 {
		return 0, false
	}
	return int64(bytes), true
}
