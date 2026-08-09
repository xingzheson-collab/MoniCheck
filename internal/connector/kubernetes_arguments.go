package connector

import (
	"strings"

	"gopkg.in/yaml.v3"
)

type kubernetesArgumentSummary struct {
	FeatureDeclared             bool
	FeatureCount                int
	FeatureInvalidCount         int
	FeatureDuplicateCount       int
	AdditionalArgsDeclared      bool
	AdditionalArgCount          int
	AdditionalArgInvalidCount   int
	AdditionalArgDuplicateCount int
}

func parseKubernetesArguments(spec *yaml.Node) kubernetesArgumentSummary {
	summary := kubernetesArgumentSummary{}
	features := yamlMappingValue(spec, "enableFeatures")
	summary.FeatureDeclared = yamlValueDeclared(features)
	featureNames := map[string]int{}
	if summary.FeatureDeclared {
		if features.Kind != yaml.SequenceNode {
			summary.FeatureInvalidCount = 1
		} else {
			for _, item := range features.Content {
				if item.Kind != yaml.ScalarNode || strings.TrimSpace(item.Value) == "" {
					summary.FeatureInvalidCount++
					continue
				}
				featureNames[strings.TrimSpace(item.Value)]++
				summary.FeatureCount++
			}
		}
	}
	summary.FeatureDuplicateCount = duplicateKubernetesArgumentNameCount(featureNames)
	args := yamlMappingValue(spec, "additionalArgs")
	summary.AdditionalArgsDeclared = yamlValueDeclared(args)
	argNames := map[string]int{}
	if summary.AdditionalArgsDeclared {
		if args.Kind != yaml.SequenceNode {
			summary.AdditionalArgInvalidCount = 1
		} else {
			for _, item := range args.Content {
				if item.Kind != yaml.MappingNode {
					summary.AdditionalArgInvalidCount++
					continue
				}
				name := strings.TrimSpace(yamlScalarValue(yamlMappingValue(item, "name")))
				if name == "" {
					summary.AdditionalArgInvalidCount++
					continue
				}
				argNames[name]++
				summary.AdditionalArgCount++
			}
		}
	}
	summary.AdditionalArgDuplicateCount = duplicateKubernetesArgumentNameCount(argNames)
	return summary
}

func duplicateKubernetesArgumentNameCount(names map[string]int) int {
	duplicates := 0
	for _, count := range names {
		if count > 1 {
			duplicates += count - 1
		}
	}
	return duplicates
}
