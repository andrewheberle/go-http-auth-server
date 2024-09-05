package sp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/crewjam/saml/samlsp"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DbAttributeStore struct {
	db *pgxpool.Pool
}

func NewDbAttributeStore(name, dsn string) (*DbAttributeStore, error) {
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, err
	}

	// set up table name
	var table string
	if name != "" {
		table = fmt.Sprintf("%s_store", name)
	} else {
		table = "store"
	}

	// table schema
	schema := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
id text PRIMARY KEY NOT NULL,
value jsonb DEFAULT '{}'::jsonb NOT NULL
)`, table)

	if _, err := db.Exec(context.Background(), schema); err != nil {
		return nil, err
	}

	return &DbAttributeStore{db}, nil
}

func (s *DbAttributeStore) Get(id string) (samlsp.Attributes, error) {
	var attrs samlsp.Attributes

	row := s.db.QueryRow(context.Background(), "SELECT value FROM store WHERE id=$1", id)
	if err := row.Scan(&attrs); err != nil {
		return nil, err
	}

	return attrs, nil
}

func (s *DbAttributeStore) Set(id string, attrs samlsp.Attributes) {
	v, err := json.Marshal(attrs)
	if err != nil {
		slog.Error("error during json marshal", "error", err)
		return
	}

	s.db.Exec(context.Background(), "INSERT INTO store (id, value) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value::jsonb", id, v)
}

func (s *DbAttributeStore) Delete(id string) {
	s.db.Exec(context.Background(), "DELETE FROM store WHERE id=$1", id)
}

func (s *DbAttributeStore) Close() {
	s.db.Close()
}
