package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andrewheberle/go-http-auth-server/pkg/sp"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gitlab.com/andrewheberle/routerswapper"
)

var rootCmd = &cobra.Command{
	Use:   "http-auth-server",
	Short: "An authentication server for SSO",
	Long: `This is a service used by a reverse proxy to authenticate a user via
a SAML IdP in order to provide SSO to a proxied service.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRootCmd()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// command line flags
	rootCmd.Flags().String("cert", "", "HTTPS Certificate")
	rootCmd.Flags().String("key", "", "HTTPS Key")
	rootCmd.Flags().String("listen", "127.0.0.1:9091", "Listen address")
	rootCmd.Flags().String("sp-cert", "", "Service Provider Certificate")
	rootCmd.Flags().String("sp-key", "", "Service Provider Key")
	rootCmd.Flags().String("sp-url", "http://localhost:9091", "Service Provider URL")
	rootCmd.Flags().StringToString("sp-claim-mapping", sp.DefaultClaimMapping, "Mapping of claims to headers")
	rootCmd.Flags().String("idp-metadata", "", "IdP Metadata URL")
	rootCmd.Flags().String("idp-issuer", "", "IdP Issuer/Entity ID")
	rootCmd.Flags().String("idp-sso-endpoint", "", "IdP SSO/login Endpoint")
	rootCmd.Flags().String("idp-certificate", "", "IdP Certificate/Public Key")
	rootCmd.Flags().Bool("debug", false, "Enable debug logging")

	// flag requirements
	rootCmd.MarkFlagsRequiredTogether("cert", "key")
	rootCmd.MarkFlagsRequiredTogether("sp-cert", "sp-key")
	rootCmd.MarkFlagRequired("sp-cert")
	rootCmd.MarkFlagRequired("sp-key")
	rootCmd.MarkFlagsRequiredTogether("idp-issuer", "idp-sso-endpoint", "idp-certificate")
	rootCmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-issuer")
	rootCmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-sso-endpoint")
	rootCmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-certificate")
}

func initConfig() {
	// load from environment
	viper.SetEnvPrefix("auth")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// bind flags to viper
	viper.BindPFlags(rootCmd.Flags())

	// set any flags found in environment via viper
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if viper.IsSet(f.Name) && viper.GetString(f.Name) != "" {
			rootCmd.Flags().Set(f.Name, viper.GetString(f.Name))
		}
	})
}

func runRootCmd() error {
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
		return fmt.Errorf("problem with SP URL: %w", err)
	}

	// set up service provider options
	opts := []sp.ServiceProviderOption{
		sp.WithClaimMapping(viper.GetStringMapString("sp-claim-mapping")),
	}

	// handle metadata
	if m := viper.GetString("idp-metadata"); m != "" {
		metadata, err := url.Parse(m)
		if err != nil {
			return fmt.Errorf("problem parsing IdP metadata url: %w", err)
		}

		opts = append(opts, sp.WithMetadataURL(metadata))
	} else {
		metadata := sp.ServiceProviderMetadata{
			Issuer:      viper.GetString("idp-issuer"),
			Endpoint:    viper.GetString("idp-sso-endpoint"),
			NameId:      "persistent",
			Certificate: viper.GetString("idp-certificate"),
		}

		opts = append(opts, sp.WithCustomMetadata(metadata))
	}

	// set up auth provider
	provider, err := sp.NewServiceProvider(viper.GetString("sp-cert"), viper.GetString("sp-key"), root, opts...)
	if err != nil {
		return fmt.Errorf("problem setting up SP: %w", err)
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
		"sp-acs-url", provider.AcsURL().String(),
		"sp-metdata-url", provider.MetadataURL().String(),
		"sp-logout-url", provider.LogoutUrl().String(),
	)

	// create run group
	g := run.Group{}

	// add http server
	if viper.GetString("cert") == "" && viper.GetString("key") == "" {
		g.Add(func() error {
			slog.Info("web server", "action", "starting up", "tls", false)
			return srv.ListenAndServe()
		}, func(err error) {
			slog.Info("web server", "action", "shutting down", "tls", false)
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
			slog.Info("certificate reloader", "action", "starting up")
			return certinel.Start(ctx)
		}, func(err error) {
			slog.Info("certificate reloader", "action", "shutting down")
			cancel()
		})

		// set up tls config to allow reloads
		srv.TLSConfig = &tls.Config{
			GetCertificate: certinel.GetCertificate,
		}

		// add tls enabled server
		g.Add(func() error {
			slog.Info("web server", "action", "starting up", "tls", true)
			return srv.ListenAndServeTLS("", "")
		}, func(err error) {
			slog.Info("web server", "action", "shutting down", "tls", true)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
			}()
		})
	}

	// set up refresh/reload of service provider metdata
	if viper.GetString("idp-metadata") != "" {
		quit := make(chan struct{})
		g.Add(func() error {
			slog.Info("service provider refresh", "action", "started", "next", time.Now().Add(time.Hour*24))
			for {
				select {
				case <-quit:
					return nil
				default:
					time.Sleep(time.Hour * 24)

					// parse url
					metadata, _ := url.Parse(viper.GetString("idp-metadata"))
					if err != nil {
						return fmt.Errorf("problem parsing IdP metadata url: %w", err)
					}

					// set up service provider options
					opts := []sp.ServiceProviderOption{
						sp.WithClaimMapping(viper.GetStringMapString("sp-claim-mapping")),
						sp.WithMetadataURL(metadata),
					}

					// set up provider
					provider, err := sp.NewServiceProvider(viper.GetString("sp-cert"), viper.GetString("sp-key"), root, opts...)
					if err != nil {
						// not a fatal error
						slog.Error("saml service provider reload", "error", err)
						continue
					}

					// new server mux
					mux := sp.NewMux(provider)

					// swap to new mux
					rs.Swap(mux)
				}

				// some logging
				slog.Info("service provider refresh", "action", "refreshed", "next", time.Now().Add(time.Hour*24))
			}
		}, func(err error) {
			slog.Info("service provider refresh", "action", "shutting down")
			close(quit)
		})
	}

	if err := g.Run(); err != nil {
		return fmt.Errorf("problem while running: %w", err)
	}

	return nil
}
