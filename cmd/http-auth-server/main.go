package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/andrewheberle/go-http-auth-server/pkg/sp"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gitlab.com/andrewheberle/routerswapper"
)

func main() {
	// command line flags
	pflag.String("cert", "", "HTTPS Certificate")
	pflag.String("key", "", "HTTPS Key")
	pflag.String("listen", "127.0.0.1:9091", "Listen address")
	pflag.String("sp-cert", "", "Service Provider Certificate")
	pflag.String("sp-key", "", "Service Provider Key")
	pflag.String("sp-url", "http://localhost:9091", "Service Provider URL")
	pflag.StringToString("sp-claim-mapping", map[string]string{"urn:oasis:names:tc:SAML:attribute:subject-id": "remote-user", "mail": "remote-email", "displayName": "remote-name", "role": "remote-groups"}, "Mapping of claims to headers")
	pflag.String("metadata", "", "IdP Metadata URL")
	pflag.Bool("debug", false, "Enable debug logging")
	pflag.Parse()

	// bind to viper
	viper.BindPFlags(pflag.CommandLine)

	// load from environment
	viper.SetEnvPrefix("auth")
	viper.AutomaticEnv()

	// logging setup
	var logLevel = new(slog.LevelVar)
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(logHandler))
	if viper.GetBool("debug") {
		logLevel.Set(slog.LevelDebug)
	}

	// validate service provider root url
	root, err := url.Parse(viper.GetString("sp-url"))
	if err != nil {
		slog.Error("problem with SP URL", err)
		os.Exit(1)
	}

	// validate metadata url
	metadata, err := url.Parse(viper.GetString("metadata"))
	if err != nil {
		slog.Error("problem with IdP metadata URL", err)
		os.Exit(1)
	}

	// set up auth provider
	provider, err := sp.NewServiceProvider(viper.GetString("sp-cert"), viper.GetString("sp-key"), metadata, root, viper.GetStringMapString("sp-claim-mapping"))
	if err != nil {
		slog.Error("problem setting up SP", err)
		os.Exit(1)
	}

	// new server mux
	mux := sp.NewMux(provider)

	// allow swapping of mux
	rs := routerswapper.New(mux)

	// set up server
	srv := &http.Server{
		Addr:         viper.GetString("listen"),
		Handler:      rs,
		ReadTimeout:  time.Second * 3,
		WriteTimeout: time.Second * 3,
	}

	slog.Info("starting service",
		"listen", srv.Addr,
		"idp-metadata-url", metadata.String(),
		"sp-acs-url", provider.AcsURL().String(),
		"sp-metdata-url", provider.MetadataURL().String(),
		"sp-logout-url", provider.LogoutUrl().String(),
	)

	g := run.Group{}

	// add http server
	if viper.GetString("cert") == "" && viper.GetString("key") == "" {
		g.Add(func() error {
			return srv.ListenAndServe()
		}, func(err error) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
			}()
		})
	} else {
		ctx, cancel := context.WithCancel(context.Background())

		// set up cert reloader
		certinel, err := fswatcher.New(viper.GetString("cert"), viper.GetString("key"))
		if err != nil {
			slog.Error("problem setting up certificate reloads", "error", err)
			os.Exit(1)
		}

		// add cert reloader to run group
		g.Add(func() error {
			return certinel.Start(ctx)
		}, func(err error) {
			cancel()
		})

		// set up tls config to allow reloads
		srv.TLSConfig = &tls.Config{
			GetCertificate: certinel.GetCertificate,
		}

		// add tls enabled server
		g.Add(func() error {
			return srv.ListenAndServeTLS("", "")
		}, func(err error) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
			}()
		})
	}

	// set up refresh/reload of service provider metdata
	quit := make(chan struct{})
	g.Add(func() error {
		for {
			select {
			case <-quit:
				return nil
			default:
				time.Sleep(time.Hour * 24)

				// set up provider
				provider, err := sp.NewServiceProvider(viper.GetString("sp-cert"), viper.GetString("sp-key"), metadata, root, viper.GetStringMapString("sp-claim-mapping"))
				if err != nil {
					// not a fatal error
					slog.Error("provider reload", "error", err)
					return nil
				}
				slog.Info("provider reload", "reloaded", true)

				// new server mux
				mux := sp.NewMux(provider)

				// swap to new mux
				rs.Swap(mux)
			}
		}
	}, func(err error) {
		close(quit)
	})

	if err := g.Run(); err != nil {
		slog.Error("problem while running", err)
		os.Exit(1)
	}
}
