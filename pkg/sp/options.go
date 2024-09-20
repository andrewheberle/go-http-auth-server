package sp

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
)

type ServiceProviderOption func(*ServiceProvider)

func WithMetadataURL(metadata *url.URL) ServiceProviderOption {
	return func(s *ServiceProvider) {
		// populate metadata from a metadata URL
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		// fetch metadata from URL
		idpMetadata, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *metadata)
		if err != nil {
			slog.Error("error fetching metadata", "error", err)
			return
		}

		s.idpMetadata = idpMetadata
		s.idpMetadataURL = metadata
	}
}

func WithCustomMetadata(metadata ServiceProviderMetadata) ServiceProviderOption {
	return func(s *ServiceProvider) {
		// build metadata from provided values
		b, err := buildMetadata(metadata.Issuer, metadata.Endpoint, metadata.Certificate)
		if err != nil {
			slog.Error("metadata build error", "error", err)
			return
		}

		idpMetadata, err := samlsp.ParseMetadata(b)
		if err != nil {
			slog.Error("custom metadata error", "error", err)
			return
		}

		s.idpMetadata = idpMetadata
	}
}

func WithClaimMapping(mapping map[string]string) ServiceProviderOption {
	return func(s *ServiceProvider) {
		s.mapping = mapping
	}
}

func WithAttributeStore(store AttributeStore) ServiceProviderOption {
	return func(s *ServiceProvider) {
		s.store = store
	}
}

func WithMetadataRefreshInterval(d time.Duration) ServiceProviderOption {
	return func(s *ServiceProvider) {
		s.idpMetadataRefreshInterval = d
	}
}

func WithName(name string) ServiceProviderOption {
	return func(s *ServiceProvider) {
		s.name = name
	}
}

func WithOnError(fn func(w http.ResponseWriter, r *http.Request, err error)) ServiceProviderOption {
	return func(s *ServiceProvider) {
		s.onerror = fn
	}
}
