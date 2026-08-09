package graph

import (
	"context"
	"sort"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

type Graph struct {
	resources     map[string]model.Resource
	relationships []model.Relationship
	incoming      map[string][]model.Relationship
	outgoing      map[string][]model.Relationship
}

type Direction string

const (
	DirectionUpstream   Direction = "upstream"
	DirectionDownstream Direction = "downstream"
)

func Build(ctx context.Context, resources storage.ResourceRepository, relationships storage.RelationshipRepository) (*Graph, error) {
	resourceList, err := resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	relationshipList, err := relationships.List(ctx)
	if err != nil {
		return nil, err
	}

	return New(resourceList, relationshipList), nil
}

// New builds a graph while preserving dangling relationships so governance
// analyzers can detect references to resources that do not exist.
func New(resourceList []model.Resource, relationshipList []model.Relationship) *Graph {
	return newGraph(resourceList, relationshipList, false)
}

// NewBounded builds a graph from an already scoped inventory and removes
// relationships that cross that inventory boundary.
func NewBounded(resourceList []model.Resource, relationshipList []model.Relationship) *Graph {
	return newGraph(resourceList, relationshipList, true)
}

func newGraph(resourceList []model.Resource, relationshipList []model.Relationship, bounded bool) *Graph {
	g := &Graph{
		resources:     make(map[string]model.Resource, len(resourceList)),
		relationships: make([]model.Relationship, 0, len(relationshipList)),
		incoming:      make(map[string][]model.Relationship),
		outgoing:      make(map[string][]model.Relationship),
	}
	for _, resource := range resourceList {
		g.resources[resource.ID] = resource
	}
	for _, relationship := range relationshipList {
		if bounded {
			if _, ok := g.resources[relationship.FromID]; !ok {
				continue
			}
			if _, ok := g.resources[relationship.ToID]; !ok {
				continue
			}
		}
		g.relationships = append(g.relationships, relationship)
		g.outgoing[relationship.FromID] = append(g.outgoing[relationship.FromID], relationship)
		g.incoming[relationship.ToID] = append(g.incoming[relationship.ToID], relationship)
	}
	return g
}

func (g *Graph) Incoming(resourceID string) []model.Relationship {
	return append([]model.Relationship(nil), g.incoming[resourceID]...)
}

func (g *Graph) Outgoing(resourceID string) []model.Relationship {
	return append([]model.Relationship(nil), g.outgoing[resourceID]...)
}

func (g *Graph) Resource(id string) (model.Resource, bool) {
	resource, ok := g.resources[id]
	return resource, ok
}

func (g *Graph) Resources() []model.Resource {
	resources := make([]model.Resource, 0, len(g.resources))
	for _, resource := range g.resources {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ID < resources[j].ID
	})
	return resources
}

func (g *Graph) Relationships() []model.Relationship {
	return append([]model.Relationship(nil), g.relationships...)
}

func (g *Graph) Traverse(startID string, direction Direction, depth int) []model.Relationship {
	if depth <= 0 {
		depth = 1
	}

	type queueItem struct {
		id    string
		depth int
	}

	queue := []queueItem{{id: startID, depth: 0}}
	visitedNodes := map[string]bool{startID: true}
	visitedRelationships := make(map[string]bool)
	result := make([]model.Relationship, 0)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= depth {
			continue
		}

		var relationships []model.Relationship
		switch direction {
		case DirectionUpstream:
			relationships = g.Incoming(current.id)
		default:
			relationships = g.Outgoing(current.id)
		}

		for _, relationship := range relationships {
			if !visitedRelationships[relationship.ID] {
				result = append(result, relationship)
				visitedRelationships[relationship.ID] = true
			}

			nextID := relationship.ToID
			if direction == DirectionUpstream {
				nextID = relationship.FromID
			}
			if visitedNodes[nextID] {
				continue
			}
			visitedNodes[nextID] = true
			queue = append(queue, queueItem{id: nextID, depth: current.depth + 1})
		}
	}

	return result
}
