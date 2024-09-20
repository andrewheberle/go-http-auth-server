package sp

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/karlseguin/ccache/v3"
)

type MemoryAttributeStore struct {
	ttl   time.Duration
	store *ccache.Cache[samlsp.Attributes]
}

func NewMemoryAttributeStore(ttl time.Duration) *MemoryAttributeStore {
	return &MemoryAttributeStore{
		store: ccache.New(ccache.Configure[samlsp.Attributes]()),
	}
}

func (s *MemoryAttributeStore) Get(id string) (samlsp.Attributes, error) {
	if item := s.store.Get(id); item != nil {
		slog.Debug("getting attributes from store", "id", id, "attrs", item.Value())

		return item.Value(), nil
	}

	return nil, fmt.Errorf("not found")
}

func (s *MemoryAttributeStore) Set(id string, attrs samlsp.Attributes) {
	if s.store == nil {
		s.store = ccache.New(ccache.Configure[samlsp.Attributes]())
	}

	slog.Debug("setting attributes in store", "id", id, "attrs", attrs)

	s.store.Set(id, attrs, s.ttl)
}

func (s *MemoryAttributeStore) Delete(id string) {
	if s.store == nil {
		return
	}

	slog.Debug("deleting attributes in store", "id", id)

	s.store.Delete(id)
}
