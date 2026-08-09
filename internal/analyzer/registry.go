package analyzer

import "sort"

type Registry struct {
	analyzers map[string]Analyzer
}

func NewRegistry() *Registry {
	return &Registry{analyzers: make(map[string]Analyzer)}
}

func (r *Registry) Register(analyzer Analyzer) {
	r.analyzers[analyzer.ID()] = analyzer
}

func (r *Registry) List() []Analyzer {
	analyzers := make([]Analyzer, 0, len(r.analyzers))
	for _, analyzer := range r.analyzers {
		analyzers = append(analyzers, analyzer)
	}
	sort.Slice(analyzers, func(i, j int) bool {
		return analyzers[i].ID() < analyzers[j].ID()
	})
	return analyzers
}

func (r *Registry) Get(id string) (Analyzer, bool) {
	analyzer, ok := r.analyzers[id]
	return analyzer, ok
}
