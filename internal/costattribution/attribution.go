package costattribution

import (
	"sort"
	"strings"

	"monicheck/internal/model"
)

const (
	StateAllocated   = "ALLOCATED"
	StateUnallocated = "UNALLOCATED"
	StateAmbiguous   = "AMBIGUOUS"
)

type Dimension struct {
	Name string
	Keys []string
}

var dimensions = []Dimension{
	{Name: "team", Keys: []string{"team", "owner_team", "responsible_team"}},
	{Name: "project", Keys: []string{"project", "project_id", "project_name"}},
	{Name: "namespace", Keys: []string{"namespace", "kubernetes_namespace", "k8s_namespace"}},
	{Name: "service", Keys: []string{model.MetadataService, "service_name"}},
	{Name: "owner", Keys: []string{model.MetadataOwner, "responsible_owner"}},
	{Name: "cluster", Keys: []string{"cluster", "cluster_name"}},
}

func Dimensions() []Dimension {
	result := make([]Dimension, len(dimensions))
	for index, dimension := range dimensions {
		result[index] = Dimension{
			Name: dimension.Name,
			Keys: append([]string(nil), dimension.Keys...),
		}
	}
	return result
}

func SupportedNames() []string {
	result := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		result = append(result, dimension.Name)
	}
	return result
}

func NormalizeDimensions(values []string) ([]string, []string) {
	supported := make(map[string]bool, len(dimensions))
	for _, dimension := range dimensions {
		supported[dimension.Name] = true
	}
	result := make([]string, 0, len(values))
	invalid := make([]string, 0)
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		if !supported[value] {
			invalid = append(invalid, value)
			continue
		}
		result = append(result, value)
	}
	return result, invalid
}

func Resolve(resource model.Resource, dimensionName string) (string, string, int) {
	var definition *Dimension
	for index := range dimensions {
		if dimensions[index].Name == dimensionName {
			definition = &dimensions[index]
			break
		}
	}
	if definition == nil {
		return StateUnallocated, "", 0
	}
	values := map[string]string{}
	for _, key := range definition.Keys {
		for _, value := range []string{resource.Labels[key], resource.Metadata[key]} {
			value = strings.TrimSpace(value)
			if value != "" {
				values[strings.ToLower(value)] = value
			}
		}
	}
	if dimensionName == "cluster" {
		if value := strings.TrimSpace(resource.Source.Cluster); value != "" {
			values[strings.ToLower(value)] = value
		}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i]) < strings.ToLower(result[j])
	})
	switch len(result) {
	case 0:
		return StateUnallocated, "", 0
	case 1:
		return StateAllocated, result[0], 1
	default:
		return StateAmbiguous, "", len(result)
	}
}
