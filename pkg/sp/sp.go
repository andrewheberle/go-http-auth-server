package sp

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
)

type ServiceProvider struct {
	idpMetadata *saml.EntityDescriptor
	mw          *samlsp.Middleware
	mapping     map[string]string
	root        *url.URL
	store       AttributeStore
}

var requiredHeaders = []string{
	"X-Forwarded-Proto",
	"X-Forwarded-Method",
	"X-Forwarded-Host",
	"X-Forwarded-URI",
	"X-Forwarded-For",
}

var DefaultClaimMapping = map[string]string{"remote-user": "urn:oasis:names:tc:SAML:attribute:subject-id", "remote-email": "mail", "remote-name": "displayName", "remote-groups": "role"}

func NewServiceProvider(cert, key string, root *url.URL, options ...ServiceProviderOption) (*ServiceProvider, error) {
	// set up new service provider
	serviceProvider := &ServiceProvider{
		root:    root,
		mapping: DefaultClaimMapping,
	}

	// parse certificate and key files
	keyPair, err := loadkeypair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("problem loading key pair: %w", err)
	}

	// apply options
	for _, o := range options {
		o(serviceProvider)
	}

	// check that metadata is set
	if serviceProvider.idpMetadata == nil {
		return nil, fmt.Errorf("metadata was not set")
	}

	// set default store
	if serviceProvider.store == nil {
		serviceProvider.store = NewMemoryAttributeStore()
	}

	// samlsp options
	opts := samlsp.Options{
		URL:               *root,
		EntityID:          root.String(),
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       serviceProvider.idpMetadata,
		AllowIDPInitiated: true,
		SignRequest:       true,
		LogoutBindings:    []string{saml.HTTPPostBinding, saml.HTTPRedirectBinding},
	}

	// create middleware
	mw, err := samlsp.New(opts)
	if err != nil {
		return nil, fmt.Errorf("new samlsp error: %w", err)
	}

	// set SHA256 as the signature method
	mw.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	// set up URLs based on provided root

	// metadata
	m, err := url.JoinPath(root.String(), "/saml/metadata")
	if err != nil {
		return nil, fmt.Errorf("metadata url error: %w", err)
	}
	mu, err := url.Parse(m)
	if err != nil {
		return nil, fmt.Errorf("metadata url error: %w", err)
	}
	mw.ServiceProvider.MetadataURL = *mu

	// acs url
	a, err := url.JoinPath(root.String(), "/saml/acs")
	if err != nil {
		return nil, fmt.Errorf("acs url error: %w", err)
	}
	au, err := url.Parse(a)
	if err != nil {
		return nil, fmt.Errorf("acs url error: %w", err)
	}
	mw.ServiceProvider.AcsURL = *au

	// slo url
	s, err := url.JoinPath(root.String(), "/saml/slo")
	if err != nil {
		return nil, fmt.Errorf("slo url error: %w", err)
	}
	su, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("slo url error: %w", err)
	}
	mw.ServiceProvider.SloURL = *su

	// use custom request tracker
	tracker := DefaultRequestTracker(opts, &mw.ServiceProvider)
	mw.RequestTracker = tracker

	// set up custom session codec
	session := mw.Session.(samlsp.CookieSessionProvider)
	session.Codec = JWTSessionCodec{session.Codec.(samlsp.JWTSessionCodec), serviceProvider.store}
	mw.Session = session

	// set up custom session provider
	if err := setSessionProvider(root, mw); err != nil {
		return nil, fmt.Errorf("session provider error: %w", err)
	}

	slog.Debug("session provider setup (outside)", "domain", mw.Session.(samlsp.CookieSessionProvider).Domain)

	serviceProvider.mw = mw

	return serviceProvider, nil
}

func (s *ServiceProvider) ForwardAuthHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("got request", "headers", r.Header)

	// check provided headers
	if err := s.checkHeaders(r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		slog.Error("required header not found", "src", r.RemoteAddr, "error", err)
		return
	}

	// claims to return
	headers := []string{"remote-user", "remote-name", "remote-email", "remote-groups"}

	session, err := s.mw.Session.GetSession(r)
	if session != nil {
		// get session attributes
		attributes, ok := session.(samlsp.SessionWithAttributes)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// convert to a map of claims
		claims := s.mapAttributes(attributes.GetAttributes())

		// set headers to return
		for _, h := range headers {
			if claim, ok := claims[h]; ok {
				w.Header().Set(h, claim)
			}
		}

		// response is ok
		w.WriteHeader(http.StatusOK)

		return
	}

	// if no session exists then return redirect
	if err == samlsp.ErrNoSession {
		slog.Info(
			"no session found",
			"for", r.Header.Get("X-Forwarded-For"),
			"proto", r.Header.Get("X-Forwarded-Proto"),
			"method", r.Header.Get("X-Forwarded-Method"),
			"uri", r.Header.Get("X-Forwarded-URI"),
			"host", r.Header.Get("X-Forwarded-Host"))

		// do start of saml auth process to return redirect
		s.doAuthFlow(w, r)

		slog.Debug("response", "headers", w.Header().Clone())
		return
	}

	s.mw.OnError(w, r, err)
}

func (s *ServiceProvider) SamlHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case s.AcsURL().Path:
		s.mw.ServeACS(w, r)
		return
	case s.MetadataURL().Path:
		s.mw.ServeMetadata(w, r)
		return
	case s.LogoutUrl().Path:
		s.LogoutHandler(w, r)
		return
	}

	http.NotFoundHandler().ServeHTTP(w, r)
}

func (s *ServiceProvider) AcsURL() *url.URL {
	return &s.mw.ServiceProvider.AcsURL
}

func (s *ServiceProvider) LoginUrl() *url.URL {
	logout, _ := url.JoinPath(s.root.String(), "/saml/login")
	u, _ := url.Parse(logout)
	return u
}

func (s *ServiceProvider) LogoutUrl() *url.URL {
	logout, _ := url.JoinPath(s.root.String(), "/saml/logout")
	u, _ := url.Parse(logout)
	return u
}

func (s *ServiceProvider) MetadataURL() *url.URL {
	return &s.mw.ServiceProvider.MetadataURL
}

func (s *ServiceProvider) VerifyURL() *url.URL {
	u, err := url.JoinPath(s.root.String(), "/api/verify")
	if err != nil {
		// this is something that cannot be recovered from
		panic(err)
	}

	verify, err := url.Parse(u)
	if err != nil {
		// this is also something that cannot be recovered from (and should not occur)
		panic(err)
	}

	return verify
}

func (s *ServiceProvider) ForwardAuthURL() *url.URL {
	u, err := url.JoinPath(s.root.String(), "/api/authz/forward-auth")
	if err != nil {
		// this is something that cannot be recovered from
		panic(err)
	}

	verify, err := url.Parse(u)
	if err != nil {
		// this is also something that cannot be recovered from (and should not occur)
		panic(err)
	}

	return verify
}

func (s *ServiceProvider) ACSHandler(w http.ResponseWriter, r *http.Request) {
	s.mw.ServeACS(w, r)
}

func (s *ServiceProvider) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	s.mw.ServeMetadata(w, r)
}

func (s *ServiceProvider) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	templ := string(`
	<html>
	  <head>
	  </head>
	  <body>
	  <h1>{{ .Message }}</h1>
	  </body>
	</html>`)

	t, err := template.New("logout").Parse(templ)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := s.mw.Session.GetSession(r); err != nil {
		t.Execute(w, struct{ Message string }{"Already Logged Out"})
		return
	}

	if err := s.mw.Session.DeleteSession(w, r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.Execute(w, struct{ Message string }{"Logged Out"})
}

func (s *ServiceProvider) HomeHandler(w http.ResponseWriter, r *http.Request) {
	templ := string(`
	<html>
	  <head>
	  </head>
	  <body>
	  <h1>Welcome</h1>
	  <h2>User Information</h2>
	  <div>User: {{ index .Data "remote-user" }}</div>
	  <div>Name: {{ index .Data "remote-name" }}</div>
	  <div>Email: {{ index .Data "remote-email" }}</div>
	  <h2>Service Provider Information</h2>
	  <div>Assertion Consumer Service URL: {{ .AcsURL }}
	  <div>Entity ID: {{ .EntityID }}
	  <div>Metadata URL: {{ .MetadataURL }}
	  </body>
	</html>`)

	t, err := template.New("home").Parse(templ)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := s.mw.Session.GetSession(r)
	if session != nil {
		// get session attributes
		attributes, ok := session.(samlsp.SessionWithAttributes)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// convert to a map of claims
		claims := s.mapAttributes(attributes.GetAttributes())

		// execute template
		t.Execute(w, struct {
			Data        map[string]string
			AcsURL      string
			EntityID    string
			MetadataURL string
			LogoutURL   string
		}{
			Data:        claims,
			AcsURL:      s.mw.ServiceProvider.AcsURL.String(),
			EntityID:    s.mw.ServiceProvider.EntityID,
			MetadataURL: s.mw.ServiceProvider.MetadataURL.String(),
			LogoutURL:   s.mw.ServiceProvider.SloURL.String(),
		})

		return
	}

	w.WriteHeader(http.StatusInternalServerError)
}

func NewMux(s *ServiceProvider) *http.ServeMux {
	// new server mux
	mux := http.NewServeMux()

	// set up auth endpoints
	mux.HandleFunc(s.VerifyURL().Path, s.ForwardAuthHandler)
	mux.HandleFunc(s.ForwardAuthURL().Path, s.ForwardAuthHandler)

	// set up saml endpoints
	mux.HandleFunc(s.AcsURL().Path, s.ACSHandler)
	mux.HandleFunc(s.MetadataURL().Path, s.MetadataHandler)
	mux.HandleFunc(s.LogoutUrl().Path, s.LogoutHandler)

	// login endpoint
	mux.Handle(s.LoginUrl().Path, s.RequireAccount(http.HandlerFunc(s.HomeHandler)))

	return mux
}

func (s *ServiceProvider) doAuthFlow(w http.ResponseWriter, r *http.Request) {
	// create new request reader and writer
	req, err := http.NewRequest(r.Header.Get("X-Forwarded-Method"), fmt.Sprintf("%s://%s%s", r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-URI")), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error("error building request", "err", err)
		return
	}
	rr := httptest.NewRecorder()

	// use current headers
	req.Header = r.Header
	slog.Debug("new request", "headers", req.Header)

	// start auth flow
	s.mw.HandleStartAuthFlow(rr, req)

	// transfer headers to response
	for header, v := range rr.Result().Header {
		for _, item := range v {
			w.Header().Add(header, item)
		}
	}
	w.WriteHeader(rr.Code)
}

func (s *ServiceProvider) checkHeaders(r *http.Request) error {
	missing := make([]string, 0)

	// check provided headers
	for _, h := range requiredHeaders {
		if v := r.Header.Get(h); v == "" {
			missing = append(missing, h)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("missing headers: %s", strings.Join(missing, ", "))
	}

	return nil
}

func (s *ServiceProvider) mapAttributes(attributes samlsp.Attributes) (claims map[string]string) {
	claims = make(map[string]string)

	slog.Debug("claim mapping", "attributes", attributes)

	// Do mapping if non-nil
	if s.mapping != nil {
		for header, claim := range s.mapping {
			slog.Debug("claim mapping", "claim", claim, "header", header)
			if attr := attributes.Get(claim); attr != "" {
				slog.Debug("claim mapping", "claim", claim, "header", header, "value", attr)
				claims[header] = attr
			}
		}

		return claims
	}

	// Otherwise straight attribute -> claim
	for k := range attributes {
		claims[k] = attributes.Get(k)
	}

	return claims
}

func (s *ServiceProvider) RequireAccount(handler http.Handler) http.Handler {
	return s.mw.RequireAccount(handler)
}

func loadkeypair(cert, key string) (tls.Certificate, error) {
	// parse certificate and key files
	keyPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}

	return keyPair, nil
}

func setSessionProvider(root *url.URL, mw *samlsp.Middleware) error {
	session, ok := mw.Session.(samlsp.CookieSessionProvider)
	if !ok {
		return fmt.Errorf("could not set up custom cookie session provider")
	}

	slog.Debug("setSessionProvider", "hostname", root.Hostname(), "domain", session.Domain)

	if d := getDomain(root); d == "" {
		return fmt.Errorf("this should never happen")
	} else {
		session.Domain = d
	}
	slog.Debug("session provider setup", "domain", session.Domain)
	mw.Session = session

	return nil
}

func getDomain(root *url.URL) string {
	hsplit := strings.Split(root.Hostname(), ".")
	if len(hsplit) == 0 {
		return ""
	}

	if len(hsplit) == 1 {
		return hsplit[0]
	}

	return strings.Join(hsplit[1:], ".")
}

func buildMetadata(issuer, endpoint, nameid, certificate string) ([]byte, error) {
	var metadataTemplate = template.Must(template.New("").Parse(`<?xml version="1.0"?>
	<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="{{ .ValidUntil }}" entityID="{{ .Issuer }}">
	  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="signing">
		  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			  <ds:X509Certificate>{{ .Certificate }}</ds:X509Certificate>
			</ds:X509Data>
		  </ds:KeyInfo>
		</md:KeyDescriptor>
		<md:KeyDescriptor use="encryption">
		  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			  <ds:X509Certificate>{{ .Certificate }}</ds:X509Certificate>
			</ds:X509Data>
		  </ds:KeyInfo>
		</md:KeyDescriptor>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:{{ .NameId }}</md:NameIDFormat>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{{ .Endpoint }}"/>
	  </md:IDPSSODescriptor>
	</md:EntityDescriptor>`))

	buf := new(bytes.Buffer)

	switch nameid {
	case "persistent", "transient", "kerberos", "entity":
		data := struct {
			Issuer, Endpoint, NameId, Certificate, ValidUntil string
		}{
			issuer, endpoint, nameid, certificate, time.Now().AddDate(0, 3, 0).Format(time.RFC3339),
		}
		if err := metadataTemplate.Execute(buf, data); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid SAML 2.0 NameId Format specified: %s", nameid)
	}

	return buf.Bytes(), nil
}

type ServiceProviderMetadata struct {
	Issuer, Endpoint, NameId, Certificate string
}
