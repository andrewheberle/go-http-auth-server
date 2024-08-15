package sp

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/crewjam/saml/samlsp"
	"github.com/golang-jwt/jwt/v4"
)

type JWTSessionCodec struct {
	samlsp.JWTSessionCodec
	store *AttributeStore
}

func (c JWTSessionCodec) Encode(s samlsp.Session) (string, error) {
	claims := s.(samlsp.JWTSessionClaims) // this will panic if you pass the wrong kind of session

	slog.Debug("encoding claims", "claims", claims)
	// save attributes to store
	c.store.Set(claims.Id, claims.Attributes)
	claims.Attributes = nil

	token := jwt.NewWithClaims(c.SigningMethod, claims)
	signedString, err := token.SignedString(c.Key)
	if err != nil {
		return "", err
	}

	return signedString, nil
}

func (c JWTSessionCodec) Decode(signed string) (samlsp.Session, error) {
	parser := jwt.Parser{
		ValidMethods: []string{c.SigningMethod.Alg()},
	}
	claims := samlsp.JWTSessionClaims{}
	_, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return c.Key.Public(), nil
	})
	// TODO(ross): check for errors due to bad time and return ErrNoSession
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(c.Audience, true) {
		return nil, fmt.Errorf("expected audience %q, got %q", c.Audience, claims.Audience)
	}
	if !claims.VerifyIssuer(c.Issuer, true) {
		return nil, fmt.Errorf("expected issuer %q, got %q", c.Issuer, claims.Issuer)
	}
	if !claims.SAMLSession {
		return nil, errors.New("expected saml-session")
	}

	// lookup attributes
	attrs, err := c.store.Get(claims.Id)
	if err != nil {
		return nil, err
	}
	claims.Attributes = attrs

	return claims, nil
}

type AttributeStore struct {
	store map[string]samlsp.Attributes
	mu    sync.RWMutex
}

func NewAttributeStore() *AttributeStore {
	return &AttributeStore{
		store: make(map[string]samlsp.Attributes),
	}
}

func (s *AttributeStore) Get(id string) (samlsp.Attributes, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if attrs, found := s.store[id]; found {
		slog.Debug("getting attributes from store", "id", id, "attrs", attrs)

		return attrs, nil
	}

	return nil, fmt.Errorf("not found")
}

func (s *AttributeStore) Set(id string, attrs samlsp.Attributes) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		s.store = make(map[string]samlsp.Attributes)
	}

	slog.Debug("setting attributes in store", "id", id, "attrs", attrs)

	s.store[id] = attrs
}
