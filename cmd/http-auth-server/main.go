package main

import "github.com/andrewheberle/go-http-auth-server/internal/cmd"

func main() {

	cmd.Execute()

	/*
		// command line flags
		pflag.String("cert", "", "HTTPS Certificate")
		pflag.String("key", "", "HTTPS Key")
		pflag.String("listen", "127.0.0.1:9091", "Listen address")
		pflag.String("sp-cert", "samlsp.crt", "Service Provider Certificate")
		pflag.String("sp-key", "samlsp.key", "Service Provider Key")
		pflag.String("sp-url", "http://localhost:9091", "Service Provider URL")
		pflag.StringToString("sp-claim-mapping", map[string]string{"urn:oasis:names:tc:SAML:attribute:subject-id": "remote-user", "mail": "remote-email", "displayName": "remote-name", "role": "remote-groups"}, "Mapping of claims to headers")
		pflag.String("metadata", "", "IdP Metadata URL (required)")
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
		quit := make(chan struct{})
		g.Add(func() error {
			slog.Info("service provider refresh", "action", "started", "next", time.Now().Add(time.Hour*24))
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

		if err := g.Run(); err != nil {
			slog.Error("problem while running", err)
			os.Exit(1)
		}
	*/
}
