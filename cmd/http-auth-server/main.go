package main

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/andrewheberle/go-http-auth-server/pkg/sp"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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

	// set up auth endpoints
	http.HandleFunc("/api/verify", provider.ForwardAuthHandler)
	http.HandleFunc("/api/authz/forward-auth", provider.ForwardAuthHandler)

	// set up saml endpoints
	http.HandleFunc(provider.AcsURL().Path, provider.ACSHandler)
	http.HandleFunc(provider.MetadataURL().Path, provider.MetadataHandler)
	http.HandleFunc(provider.LogoutUrl().Path, provider.LogoutHandler)

	// login endpoint
	http.Handle("/login", provider.RequireAccount(http.HandlerFunc((func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Logged In."))
	}))))

	// dummy endpoint

	srv := &http.Server{
		Addr:         viper.GetString("listen"),
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

	if err := srv.ListenAndServe(); err != nil {
		slog.Error("problem with SP URL", err)
		os.Exit(1)
	}
}
