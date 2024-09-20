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
	rootCmd.Flags().String("db-connection", "", "Database connection string")
	rootCmd.Flags().String("db-prefix", "", "Database table prefix")
	rootCmd.Flags().StringP("config", "c", "", "Configuration file")
	rootCmd.Flags().Bool("debug", false, "Enable debug logging")

	// flag requirements
	rootCmd.MarkFlagsRequiredTogether("sp-cert", "sp-key")
	rootCmd.MarkFlagRequired("sp-cert")
	rootCmd.MarkFlagRequired("sp-key")
	rootCmd.MarkFlagsRequiredTogether("cert", "key")
	rootCmd.MarkFlagsRequiredTogether("idp-issuer", "idp-sso-endpoint", "idp-certificate")
	rootCmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-issuer")
	rootCmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-sso-endpoint")
	rootCmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-certificate")
	rootCmd.MarkFlagsRequiredTogether("cert", "key")
}

func initConfig() {
	// load from environment
	viper.SetEnvPrefix("auth")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// bind flags to viper
	viper.BindPFlags(rootCmd.Flags())

	// load config file if flag is set
	if config := viper.GetString("config"); config != "" {
		viper.SetConfigFile(config)
		if err := viper.ReadInConfig(); err != nil {
			slog.Error("problem loading configuration", "error", err)
			os.Exit(1)
		}

		// set sp-cert and sp-key to something just to allow things to work when using multiple SP's
		for _, name := range []string{"sp-cert", "sp-key"} {
			if !viper.IsSet(name) {
				rootCmd.Flags().Set(name, "unused")
			}
		}
	}

	// set any flags found in environment/config via viper
	rootCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if viper.IsSet(f.Name) && viper.GetString(f.Name) != "" {
			slog.Info("setting flag", "name", f.Name, "value", viper.GetString(f.Name))
			rootCmd.Flags().Set(f.Name, viper.GetString(f.Name))
		}
	})
}

type serviceProvider struct {
	Name                        string            `mapstructure:"name"`
	ServiceProviderURL          string            `mapstructure:"sp-url"`
	ServiceProviderClaimMapping map[string]string `mapstructure:"sp-claim-mapping"`
	ServiceProviderCertificate  string            `mapstructure:"sp-cert"`
	ServiceProviderKey          string            `mapstructure:"sp-key"`
	IdPMetadata                 string            `mapstructure:"idp-metadata"`
	IdPIssuer                   string            `mapstructure:"idp-issuer"`
	IdPSSOEndpoint              string            `mapstructure:"idp-sso-endpoint"`
	IdPCertificate              string            `mapstructure:"idp-certificate"`
	DatabaseConnection          string            `mapstructure:"db-connection"`
	DatabaseTablePrefix         string            `mapstructure:"db-prefix"`
}

func runRootCmd() error {
	// logging setup
	var logLevel = new(slog.LevelVar)
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(logHandler))
	if viper.GetBool("debug") {
		logLevel.Set(slog.LevelDebug)
	}

	// did we load in via a config file
	var serviceProviders []serviceProvider
	if viper.ConfigFileUsed() != "" {
		// has a list of service providers been provided?
		if viper.Get("service-providers") != nil {
			if err := viper.UnmarshalKey("service-providers", &serviceProviders); err != nil {
				return fmt.Errorf("error with service providers list: %w", err)
			}
		} else {
			var sp serviceProvider
			if err := viper.Unmarshal(&sp); err != nil {
				return fmt.Errorf("error with service provider: %w", err)
			}

			serviceProviders = []serviceProvider{sp}
		}
	}

	// create run group
	g := run.Group{}

	// new mux
	mux := http.NewServeMux()

	// set up service provider(s)
	for _, spConfig := range serviceProviders {
		// validate service provider root url
		root, err := url.Parse(spConfig.ServiceProviderURL)
		if err != nil {
			return fmt.Errorf("problem with SP URL: %w", err)
		}

		// set up service provider options
		opts := []sp.ServiceProviderOption{
			sp.WithClaimMapping(spConfig.ServiceProviderClaimMapping),
		}

		// handle metadata
		if spConfig.IdPMetadata != "" {
			metadata, err := url.Parse(spConfig.IdPMetadata)
			if err != nil {
				return fmt.Errorf("problem parsing IdP metadata url: %w", err)
			}

			opts = append(opts, sp.WithMetadataURL(metadata))
		} else {
			metadata := sp.ServiceProviderMetadata{
				Issuer:      spConfig.IdPIssuer,
				Endpoint:    spConfig.IdPSSOEndpoint,
				Certificate: spConfig.IdPCertificate,
			}

			opts = append(opts, sp.WithCustomMetadata(metadata))
		}

		// are we using a database for storing session attributes
		if dsn := spConfig.DatabaseConnection; dsn != "" {
			store, err := sp.NewDbAttributeStore(spConfig.DatabaseTablePrefix, dsn)
			if err != nil {
				return fmt.Errorf("problem setting up db attribute store: %w", err)
			}
			defer store.Close()

			opts = append(opts, sp.WithAttributeStore(store))
		}

		// set Service Provider name if provided
		if spConfig.Name != "" {
			opts = append(opts, sp.WithName(spConfig.Name))
		}

		// set up auth provider
		provider, err := sp.NewServiceProvider(spConfig.ServiceProviderCertificate, spConfig.ServiceProviderKey, root, opts...)
		if err != nil {
			return fmt.Errorf("problem setting up SP: %w", err)
		}

		// set up refresh/reload of service provider metdata
		if spConfig.IdPMetadata != "" {
			quit := make(chan struct{})
			g.Add(func() error {
				slog.Info("service provider refresh", "action", "started", "next", time.Now().Add(time.Hour*24))
				for {
					select {
					case <-quit:
						return nil
					default:
						if err := provider.RefreshMetadata(); err != nil {
							// not a fatal error
							slog.Error("saml service provider reload", "error", err)
							continue
						}
					}

					// some logging
					slog.Info("service provider refresh", "action", "refreshed", "next", time.Now().Add(time.Hour*24))
				}
			}, func(err error) {
				slog.Info("service provider refresh", "action", "shutting down")
				close(quit)
			})
		}

		// new server mux
		if err := provider.NewMux(mux); err != nil {
			return fmt.Errorf("error setting up mux: %w", err)
		}

		slog.Info("set up service provider",
			"acs-url", provider.AcsURL().String(),
			"metdata-url", provider.MetadataURL().String(),
			"logout-url", provider.LogoutUrl().String(),
			"name", spConfig.Name,
		)
	}

	// set up server
	srv := &http.Server{
		Addr:         viper.GetString("listen"),
		Handler:      mux,
		ReadTimeout:  time.Second * 3,
		WriteTimeout: time.Second * 3,
	}

	slog.Info("starting service", "listen", srv.Addr)

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

	if err := g.Run(); err != nil {
		return fmt.Errorf("problem while running: %w", err)
	}

	return nil
}
