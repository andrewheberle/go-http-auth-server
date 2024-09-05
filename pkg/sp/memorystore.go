package sp

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/crewjam/saml/samlsp"
)

type MemoryAttributeStore struct {
	store map[string]samlsp.Attributes
	mu    sync.RWMutex
}

func NewMemoryAttributeStore() (*MemoryAttributeStore, error) {
	return &MemoryAttributeStore{
		store: make(map[string]samlsp.Attributes),
	}, nil
}

func (s *MemoryAttributeStore) Get(id string) (samlsp.Attributes, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if attrs, found := s.store[id]; found {
		slog.Debug("getting attributes from store", "id", id, "attrs", attrs)

		return attrs, nil
	}

	return nil, fmt.Errorf("not found")
}

func (s *MemoryAttributeStore) Set(id string, attrs samlsp.Attributes) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		s.store = make(map[string]samlsp.Attributes)
	}

	slog.Debug("setting attributes in store", "id", id, "attrs", attrs)

	s.store[id] = attrs
}

func (s *MemoryAttributeStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		return
	}

	slog.Debug("deleting attributes in store", "id", id)

	delete(s.store, id)
}
