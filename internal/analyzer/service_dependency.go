package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighServiceDependencyFanoutAnalyzerID   = "builtin.high_service_dependency_fanout"
	CircularServiceDependencyAnalyzerID     = "builtin.circular_service_dependency"
	defaultServiceDependencyFanoutThreshold = 10
	defaultServiceDependencyNameSample      = 8
)

type HighServiceDependencyFanoutAnalyzer struct{}

func NewHighServiceDependencyFanoutAnalyzer() *HighServiceDependencyFanoutAnalyzer {
	return &HighServiceDependencyFanoutAnalyzer{}
}

func (a *HighServiceDependencyFanoutAnalyzer) ID() string {
	return HighServiceDependencyFanoutAnalyzerID
}
func (a *HighServiceDependencyFanoutAnalyzer) Name() string {
	return "High Service Dependency Fanout"
}
func (a *HighServiceDependencyFanoutAnalyzer) Version() string { return "0.1.0" }
func (a *HighServiceDependencyFanoutAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService}
}

func (a *HighServiceDependencyFanoutAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Graph == nil {
		return nil, nil
	}
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	threshold := intConfig(analysis.Config, "service_dependency_fanout_threshold", defaultServiceDependencyFanoutThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range services {
		if service.Status != model.ResourceStatusActive {
			continue
		}
		dependencies, callCount := outgoingServiceDependencies(service.ID, analysis)
		if len(dependencies) <= threshold {
			continue
		}
		names := sampledConsumerNames(dependencies, defaultServiceDependencyNameSample)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "HighServiceDependencyFanout",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("service %q directly depends on %d active services, threshold is %d", service.Name, len(dependencies), threshold),
				fmt.Sprintf("sample dependencies: %s", strings.Join(names, ", ")),
			},
			Recommendation: "评估该服务是否承担过多同步编排职责；优先拆分非核心调用、合并重复依赖，并为关键下游建立超时、重试、隔离和降级策略。",
			Metadata: map[string]string{
				"analyzer_id":      a.ID(),
				"dependency_count": strconv.Itoa(len(dependencies)),
				"call_count":       strconv.FormatUint(callCount, 10),
				"threshold":        strconv.Itoa(threshold),
				"dependencies":     strings.Join(names, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

type CircularServiceDependencyAnalyzer struct{}

func NewCircularServiceDependencyAnalyzer() *CircularServiceDependencyAnalyzer {
	return &CircularServiceDependencyAnalyzer{}
}

func (a *CircularServiceDependencyAnalyzer) ID() string { return CircularServiceDependencyAnalyzerID }
func (a *CircularServiceDependencyAnalyzer) Name() string {
	return "Circular Service Dependency"
}
func (a *CircularServiceDependencyAnalyzer) Version() string { return "0.1.0" }
func (a *CircularServiceDependencyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeService}
}

func (a *CircularServiceDependencyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Graph == nil {
		return nil, nil
	}
	services, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeService})
	if err != nil {
		return nil, err
	}
	active := make(map[string]model.Resource)
	for _, service := range services {
		if service.Status == model.ResourceStatusActive {
			active[service.ID] = service
		}
	}
	components := serviceDependencyComponents(active, analysis)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0, len(components))
	for _, component := range components {
		if !isCircularServiceComponent(component, analysis) {
			continue
		}
		members := make([]model.Resource, 0, len(component))
		for _, id := range component {
			members = append(members, active[id])
		}
		sortResourcesByTypeAndName(members)
		memberIDs := make([]string, 0, len(members))
		memberNames := make([]string, 0, len(members))
		memberSet := make(map[string]bool, len(members))
		for _, member := range members {
			memberIDs = append(memberIDs, member.ID)
			memberNames = append(memberNames, member.Name)
			memberSet[member.ID] = true
		}
		edgeCount, callCount := internalServiceDependencyStats(memberSet, analysis)
		primary := members[0]
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), strings.Join(memberIDs, ",")),
			Type:     "CircularServiceDependency",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: primary.ID, Type: primary.Type, Name: primary.Name},
			Evidence: []string{
				fmt.Sprintf("%d active services form a strongly connected dependency component with %d internal edges", len(members), edgeCount),
				fmt.Sprintf("services: %s", strings.Join(memberNames, ", ")),
			},
			Recommendation: "识别环路中的同步调用与共享职责，选择一条依赖反转、事件异步化或接口下沉；同时检查超时和重试叠加，避免故障在环路中放大。",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"service_count": strconv.Itoa(len(members)),
				"edge_count":    strconv.Itoa(edgeCount),
				"call_count":    strconv.FormatUint(callCount, 10),
				"services":      strings.Join(memberNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings, nil
}

func outgoingServiceDependencies(serviceID string, analysis Context) ([]model.Resource, uint64) {
	seen := make(map[string]bool)
	dependencies := make([]model.Resource, 0)
	var callCount uint64
	for _, relationship := range analysis.Graph.Outgoing(serviceID) {
		if relationship.Type != model.RelationshipDependsOn || seen[relationship.ToID] {
			continue
		}
		dependency, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok || dependency.Type != model.ResourceTypeService || dependency.Status != model.ResourceStatusActive {
			continue
		}
		seen[dependency.ID] = true
		dependencies = append(dependencies, dependency)
		callCount += metadataUint64(relationship.Metadata, model.MetadataAPMTopologyCallCount)
	}
	sortResourcesByTypeAndName(dependencies)
	return dependencies, callCount
}

func serviceDependencyComponents(active map[string]model.Resource, analysis Context) [][]string {
	ids := make([]string, 0, len(active))
	for id := range active {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := 0
	indices := make(map[string]int, len(ids))
	lowlink := make(map[string]int, len(ids))
	onStack := make(map[string]bool, len(ids))
	stack := make([]string, 0, len(ids))
	components := make([][]string, 0)

	var visit func(string)
	visit = func(id string) {
		indices[id] = index
		lowlink[id] = index
		index++
		stack = append(stack, id)
		onStack[id] = true

		targets := activeServiceDependencyTargets(id, active, analysis)
		for _, target := range targets {
			targetIndex, visited := indices[target]
			if !visited {
				visit(target)
				if lowlink[target] < lowlink[id] {
					lowlink[id] = lowlink[target]
				}
			} else if onStack[target] && targetIndex < lowlink[id] {
				lowlink[id] = targetIndex
			}
		}
		if lowlink[id] != indices[id] {
			return
		}
		component := make([]string, 0)
		for len(stack) > 0 {
			member := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[member] = false
			component = append(component, member)
			if member == id {
				break
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}

	for _, id := range ids {
		if _, visited := indices[id]; !visited {
			visit(id)
		}
	}
	return components
}

func activeServiceDependencyTargets(serviceID string, active map[string]model.Resource, analysis Context) []string {
	seen := make(map[string]bool)
	targets := make([]string, 0)
	for _, relationship := range analysis.Graph.Outgoing(serviceID) {
		if relationship.Type != model.RelationshipDependsOn || seen[relationship.ToID] {
			continue
		}
		if _, ok := active[relationship.ToID]; !ok {
			continue
		}
		seen[relationship.ToID] = true
		targets = append(targets, relationship.ToID)
	}
	sort.Strings(targets)
	return targets
}

func isCircularServiceComponent(component []string, analysis Context) bool {
	if len(component) > 1 {
		return true
	}
	if len(component) == 0 {
		return false
	}
	for _, relationship := range analysis.Graph.Outgoing(component[0]) {
		if relationship.Type == model.RelationshipDependsOn && relationship.ToID == component[0] {
			return true
		}
	}
	return false
}

func internalServiceDependencyStats(members map[string]bool, analysis Context) (int, uint64) {
	edgeCount := 0
	var callCount uint64
	for id := range members {
		for _, relationship := range analysis.Graph.Outgoing(id) {
			if relationship.Type != model.RelationshipDependsOn || !members[relationship.ToID] {
				continue
			}
			edgeCount++
			callCount += metadataUint64(relationship.Metadata, model.MetadataAPMTopologyCallCount)
		}
	}
	return edgeCount, callCount
}

func metadataUint64(metadata map[string]string, key string) uint64 {
	value, err := strconv.ParseUint(strings.TrimSpace(metadata[key]), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
