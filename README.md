# go-http-auth-server

[![Go Report Card](https://goreportcard.com/badge/github.com/andrewheberle/go-http-auth-server?logo=go&style=flat-square)](https://goreportcard.com/report/github.com/andrewheberle/go-http-auth-server)

This service combines some basic functionality of [Authelia](https://www.authelia.com/) with a SAML Service Provider so that HTTP authentication sub-requests to `/api/verify` or `/api/authz/forward-auth` are checked against the presence of a valid session otherwise a SAML authentication process is started.

## Overview

The process for login is:

1. A reverse proxy, such as HAProxy, gets a HTTP request from a user
2. This proxy performs a process to verify the authentiction of the user via a HTTP sub-requet to `/api/authz/forward-auth`
3. If the user is already authenticated the `/api/authz/forward-auth` returns a `HTTP 200 OK` response along with HTTP headers the proxy may use to identify the user
4. If no valid session is available, a redirect is returned to the proxy which should be returned to the user, which will start the SAML login process
