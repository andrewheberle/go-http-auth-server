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
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
)

type rootCommand struct {
	logger *slog.Logger

	// general flags
	cert   string
	key    string
	listen string
	debug  bool

	// sp flags
	spCookie       string
	spCert         string
	spKey          string
	spUrl          string
	spClaimMapping map[string]string

	// idp flags
	idpMetadata    string
	idpIssuer      string
	idpSSOEndpoint string
	idpCertificate string

	// db flags
	dbPrefix     string
	dbConnection string

	*simplecommand.Command
}

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	// general command line flags
	cmd.Flags().StringVar(&c.cert, "cert", "", "HTTPS Certificate")
	cmd.Flags().StringVar(&c.key, "key", "", "HTTPS Key")
	cmd.MarkFlagsRequiredTogether("cert", "key")
	cmd.Flags().StringVar(&c.listen, "listen", "127.0.0.1:9091", "Listen address")
	cmd.Flags().StringVarP(&c.Config, "config", "c", "", "Configuration file")
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")

	// sp command line flags
	cmd.Flags().StringVar(&c.spCookie, "sp-cookie", "token", "Cookie Name set by Service Provider")
	cmd.Flags().StringVar(&c.spCert, "sp-cert", "", "Service Provider Certificate")
	cmd.Flags().StringVar(&c.spKey, "sp-key", "", "Service Provider Key")
	cmd.MarkFlagsRequiredTogether("sp-cert", "sp-key")
	cmd.Flags().StringVar(&c.spUrl, "sp-url", "http://localhost:9091", "Service Provider URL")
	cmd.Flags().StringToStringVar(&c.spClaimMapping, "sp-claim-mapping", sp.DefaultClaimMapping, "Mapping of claims to headers")

	// IdP command line flags
	cmd.Flags().StringVar(&c.idpMetadata, "idp-metadata", "", "IdP Metadata URL")
	cmd.Flags().StringVar(&c.idpIssuer, "idp-issuer", "", "IdP Issuer/Entity ID")
	cmd.Flags().StringVar(&c.idpSSOEndpoint, "idp-sso-endpoint", "", "IdP SSO/login Endpoint")
	cmd.Flags().StringVar(&c.idpCertificate, "idp-certificate", "", "IdP Certificate/Public Key")
	cmd.MarkFlagsRequiredTogether("idp-issuer", "idp-sso-endpoint", "idp-certificate")
	cmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-issuer")
	cmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-sso-endpoint")
	cmd.MarkFlagsMutuallyExclusive("idp-metadata", "idp-certificate")

	// database flags
	cmd.Flags().StringVar(&c.dbConnection, "db-connection", "", "Database connection string")
	cmd.Flags().StringVar(&c.dbPrefix, "db-prefix", "", "Database table prefix")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// set up logger
	logLevel := new(slog.LevelVar)
	c.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	c.logger.Debug("service provider list", "list", c.serviceProviders())

	return nil
}

type serviceProvider struct {
	Name                        string            `mapstructure:"name"`
	ServiceProviderURL          string            `mapstructure:"sp-url"`
	ServiceProviderClaimMapping map[string]string `mapstructure:"sp-claim-mapping"`
	ServiceProviderCertificate  string            `mapstructure:"sp-cert"`
	ServiceProviderKey          string            `mapstructure:"sp-key"`
	ServiceProviderCookieName   string            `mapstructure:"sp-cookie"`
	IdPMetadata                 string            `mapstructure:"idp-metadata"`
	IdPIssuer                   string            `mapstructure:"idp-issuer"`
	IdPSSOEndpoint              string            `mapstructure:"idp-sso-endpoint"`
	IdPCertificate              string            `mapstructure:"idp-certificate"`
	DatabaseConnection          string            `mapstructure:"db-connection"`
	DatabaseTablePrefix         string            `mapstructure:"db-prefix"`
}

func (c *rootCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// create run group
	g := run.Group{}

	// new mux
	mux := http.NewServeMux()

	// set up service provider(s)
	for _, spConfig := range c.serviceProviders() {
		// use global values as a fallback if some values are not set
		spConfig.ServiceProviderCertificate = fallback(spConfig.ServiceProviderCertificate, c.spCert)
		spConfig.ServiceProviderKey = fallback(spConfig.ServiceProviderKey, c.spKey)
		spConfig.ServiceProviderCookieName = fallback(spConfig.ServiceProviderCookieName, c.spCookie)

		// show config in debug mode
		c.logger.Debug("setting up service provider",
			"name", spConfig.Name,
			"url", spConfig.ServiceProviderURL,
			"metadata", spConfig.IdPMetadata,
			"cert", spConfig.ServiceProviderCertificate,
			"key", spConfig.ServiceProviderKey,
		)

		// validate service provider root url
		root, err := url.Parse(spConfig.ServiceProviderURL)
		if err != nil {
			return fmt.Errorf("problem with SP URL: %w", err)
		}

		// set up service provider options
		opts := []sp.ServiceProviderOption{
			sp.WithClaimMapping(spConfig.ServiceProviderClaimMapping),
			sp.WithCookieName(spConfig.ServiceProviderCookieName),
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

		c.logger.Info("set up service provider",
			"acs-url", provider.AcsURL().String(),
			"metdata-url", provider.MetadataURL().String(),
			"logout-url", provider.LogoutUrl().String(),
			"name", spConfig.Name,
		)
	}

	// set up server
	srv := &http.Server{
		Addr:         c.listen,
		Handler:      mux,
		ReadTimeout:  time.Second * 3,
		WriteTimeout: time.Second * 3,
	}

	c.logger.Info("starting service", "listen", srv.Addr)

	// add http server
	if c.cert == "" && c.key == "" {
		g.Add(func() error {
			c.logger.Info("web server", "action", "starting up", "tls", false)
			return srv.ListenAndServe()
		}, func(err error) {
			c.logger.Info("web server", "action", "shutting down", "tls", false)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
			}()
		})
	} else {
		ctx, cancel := context.WithCancel(context.Background())

		// set up cert reloader
		certinel, err := fswatcher.New(c.cert, c.key)
		if err != nil {
			c.logger.Error("problem setting up certificate reloads", "error", err)
			os.Exit(1)
		}

		// add cert reloader to run group
		g.Add(func() error {
			c.logger.Info("certificate reloader", "action", "starting up")
			return certinel.Start(ctx)
		}, func(err error) {
			c.logger.Info("certificate reloader", "action", "shutting down")
			cancel()
		})

		// set up tls config to allow reloads
		srv.TLSConfig = &tls.Config{
			GetCertificate: certinel.GetCertificate,
		}

		// add tls enabled server
		g.Add(func() error {
			c.logger.Info("web server", "action", "starting up", "tls", true)
			return srv.ListenAndServeTLS("", "")
		}, func(err error) {
			c.logger.Info("web server", "action", "shutting down", "tls", true)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
			}()
		})
	}

	return g.Run()
}

func (c *rootCommand) serviceProviders() []serviceProvider {
	var serviceProviders []serviceProvider

	// no config file or no viper
	if c.Config == "" || c.Viper() == nil {
		return []serviceProvider{
			{
				ServiceProviderURL:          c.spUrl,
				ServiceProviderClaimMapping: c.spClaimMapping,
				ServiceProviderCertificate:  c.spCert,
				ServiceProviderKey:          c.spKey,
				ServiceProviderCookieName:   c.spCookie,
				IdPMetadata:                 c.idpMetadata,
				IdPIssuer:                   c.idpIssuer,
				IdPSSOEndpoint:              c.idpSSOEndpoint,
				IdPCertificate:              c.idpCertificate,
				DatabaseConnection:          c.dbConnection,
				DatabaseTablePrefix:         c.dbPrefix,
			},
		}
	}

	// plain config file (not a list)
	if c.Viper().Get("service-providers") == nil {
		return []serviceProvider{
			{
				ServiceProviderURL:          c.spUrl,
				ServiceProviderClaimMapping: c.spClaimMapping,
				ServiceProviderCertificate:  c.spCert,
				ServiceProviderKey:          c.spKey,
				ServiceProviderCookieName:   c.spCookie,
				IdPMetadata:                 c.idpMetadata,
				IdPIssuer:                   c.idpIssuer,
				IdPSSOEndpoint:              c.idpSSOEndpoint,
				IdPCertificate:              c.idpCertificate,
				DatabaseConnection:          c.dbConnection,
				DatabaseTablePrefix:         c.dbPrefix,
			},
		}
	}

	// try to unmarshal from list
	if err := c.Viper().UnmarshalKey("service-providers", &serviceProviders); err != nil {
		return []serviceProvider{}
	}

	return serviceProviders
}

func Execute(args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New(
			"http-auth-server",
			"An authentication server for SSO",
			simplecommand.Long(`This is a service used by a reverse proxy to authenticate a user via
a SAML IdP in order to provide SSO to a proxied service.`),
			simplecommand.WithViper("auth", strings.NewReplacer("-", "_")),
		),
	}

	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	if _, err := x.Execute(context.Background(), args); err != nil {
		return err
	}

	return nil
}

func fallback[T comparable](a, b T) T {
	var zero T

	if a == zero {
		return b
	}

	return a
}
