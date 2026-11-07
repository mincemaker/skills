// Command fakeidp is a scriptable OAuth 2.0 / OIDC provider for RP audits.
//
// It is strict by default: codes are single use, bound to client_id,
// redirect_uri and the PKCE challenge, and ID tokens are ES256-signed.
// Tests change its answers through /_audit/scenario and read what the RP
// sent through /_audit/requests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Scenario is what a test may tamper with. The zero value is a correct IdP.
type Scenario struct {
	IssParam        bool           `json:"iss_param"`         // add iss to the authorization response and advertise it
	IssOverride     string         `json:"iss_override"`      // iss value sent in the authorization response
	IDToken         map[string]any `json:"id_token"`          // claim overrides; a null value removes the claim
	Alg             string         `json:"alg"`               // "none" sends an unsigned ID token
	BadSignature    bool           `json:"bad_signature"`     // corrupt the ID token signature
	UserinfoSub     string         `json:"userinfo_sub"`      // sub (and id) returned by userinfo
	OmitAccessToken bool           `json:"omit_access_token"` // token response without access_token
}

type code struct {
	clientID, redirectURI, challenge, method, nonce, scope, user string
	used                                                        bool
}

// Request is one request the RP sent to the IdP.
type Request struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Query         string `json:"query"`
	Body          string `json:"body"`
	Authorization string `json:"authorization"`
	User          string `json:"user,omitempty"` // owner of the access token the request carried, if known
}

type server struct {
	issuer string
	key    *ecdsa.PrivateKey

	mu       sync.Mutex
	scenario Scenario
	codes    map[string]*code
	tokens   map[string]string // access token -> user
	requests []Request
}

func newServer(issuer string) *server {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	s := &server{issuer: strings.TrimRight(issuer, "/"), key: key}
	s.reset()
	return s
}

func (s *server) reset() {
	s.scenario = Scenario{}
	s.codes = map[string]*code{}
	s.tokens = map[string]string{}
	s.requests = nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := r.URL.Path
	if strings.HasPrefix(p, "/_audit/") {
		s.admin(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	s.requests = append(s.requests, Request{r.Method, p, r.URL.RawQuery, string(body), r.Header.Get("Authorization"), s.tokens[accessToken(r)]})

	// ponytail: routes by path keywords so a test only swaps the origin of the
	// real provider URL (Google, X, ...). Add an explicit route table if two
	// endpoints of one provider ever collide.
	lp := strings.ToLower(p) // providers spell paths like /oauth/v2/accessToken
	switch {
	case strings.HasSuffix(lp, "/.well-known/openid-configuration"):
		s.discovery(w)
	case strings.Contains(lp, "revoke"):
		writeJSON(w, 200, map[string]any{})
	case strings.Contains(lp, "authoriz") || strings.HasSuffix(lp, "/auth"):
		s.authorize(w, r)
	case strings.Contains(lp, "token"):
		s.token(w, r, body)
	case strings.Contains(lp, "jwks") || strings.Contains(lp, "certs"):
		s.jwks(w)
	case strings.Contains(lp, "userinfo") || strings.HasSuffix(lp, "/users/me") || strings.HasSuffix(lp, "/user"):
		s.userinfo(w, r)
	case accessToken(r) != "":
		// any other API of the provider (e.g. /photos/me) answers as the token's user
		s.userinfo(w, r)
	default:
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	}
}

func (s *server) admin(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_audit/scenario":
		var sc Scenario
		if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.scenario = sc
		writeJSON(w, 200, sc)
	case "/_audit/requests":
		writeJSON(w, 200, append([]Request{}, s.requests...))
	case "/_audit/reset":
		s.reset()
		writeJSON(w, 200, map[string]any{})
	default:
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	}
}

func (s *server) discovery(w http.ResponseWriter) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"userinfo_endpoint":                     s.issuer + "/userinfo",
		"jwks_uri":                              s.issuer + "/jwks",
		"revocation_endpoint":                   s.issuer + "/revoke",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"authorization_response_iss_parameter_supported": s.scenario.IssParam,
	})
}

// authorize consents automatically. The user is "victim" unless the test
// appends _user=<name> to the authorization URL.
func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" {
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "error_description": "redirect_uri"})
		return
	}
	user := q.Get("_user")
	if user == "" {
		user = "victim"
	}
	c := randomString()
	s.codes[c] = &code{q.Get("client_id"), q.Get("redirect_uri"), q.Get("code_challenge"), q.Get("code_challenge_method"), q.Get("nonce"), q.Get("scope"), user, false}

	rq := redirect.Query()
	rq.Set("code", c)
	if st := q.Get("state"); st != "" {
		rq.Set("state", st)
	}
	if s.scenario.IssParam || s.scenario.IssOverride != "" {
		iss := s.issuer
		if s.scenario.IssOverride != "" {
			iss = s.scenario.IssOverride
		}
		rq.Set("iss", iss)
	}
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// token accepts form, query and JSON parameters, because RP libraries send
// all three. Client authentication is not checked: that is the AS's job.
func (s *server) token(w http.ResponseWriter, r *http.Request, body []byte) {
	params := map[string]string{}
	for k, v := range r.URL.Query() {
		params[k] = v[0]
	}
	if strings.Contains(r.Header.Get("Content-Type"), "json") {
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		for k, v := range m {
			params[k] = fmt.Sprint(v)
		}
	} else if f, err := url.ParseQuery(string(body)); err == nil {
		for k, v := range f {
			params[k] = v[0]
		}
	}

	fail := func(desc string) {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": desc})
	}
	c, ok := s.codes[params["code"]]
	switch {
	case !ok:
		fail("unknown code")
		return
	case c.used:
		fail("code reused")
		return
	case params["redirect_uri"] != "" && params["redirect_uri"] != c.redirectURI:
		fail("redirect_uri mismatch")
		return
	case c.challenge == "" && params["code_verifier"] != "":
		fail("code_verifier without code_challenge")
		return
	case c.challenge != "" && !pkceOK(c.challenge, c.method, params["code_verifier"]):
		fail("code_verifier mismatch")
		return
	}
	c.used = true

	at := randomDigits()
	s.tokens[at] = c.user
	scope := c.scope
	if scope == "" {
		scope = "openid"
	}
	resp := map[string]any{"token_type": "Bearer", "expires_in": 3600, "scope": scope, "refresh_token": randomString()}
	if !s.scenario.OmitAccessToken {
		resp["access_token"] = at
	}
	if strings.Contains(" "+scope+" ", " openid ") {
		resp["id_token"] = s.idToken(c)
	}
	writeJSON(w, 200, resp)
}

func pkceOK(challenge, method, verifier string) bool {
	if verifier == "" {
		return false
	}
	if method == "plain" {
		return verifier == challenge
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func (s *server) idToken(c *code) string {
	now := time.Now().Unix()
	claims := map[string]any{"iss": s.issuer, "aud": c.clientID, "sub": c.user, "iat": now, "exp": now + 300}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	for k, v := range s.scenario.IDToken {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	alg := "ES256"
	if s.scenario.Alg == "none" {
		alg = "none"
	}
	input := b64json(map[string]string{"alg": alg, "kid": "k1", "typ": "JWT"}) + "." + b64json(claims)
	if alg == "none" {
		return input + "."
	}
	sum := sha256.Sum256([]byte(input))
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		panic(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), sg.FillBytes(make([]byte, 32))...)
	if s.scenario.BadSignature {
		sig[0] ^= 0xff
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *server) jwks(w http.ResponseWriter) {
	pub, err := s.key.PublicKey.ECDH()
	if err != nil {
		panic(err)
	}
	b := pub.Bytes() // 0x04 || X || Y
	enc := base64.RawURLEncoding.EncodeToString
	writeJSON(w, 200, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1", "x": enc(b[1:33]), "y": enc(b[33:]),
	}}})
}

// userinfo answers in a shape several providers' clients accept: sub for
// OIDC, id for Google v2 and GitHub, data for X.
func (s *server) userinfo(w http.ResponseWriter, r *http.Request) {
	user, ok := s.tokens[accessToken(r)]
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	sub := user
	if s.scenario.UserinfoSub != "" {
		sub = s.scenario.UserinfoSub
	}
	writeJSON(w, 200, map[string]any{
		"sub": sub, "id": sub, "name": user, "email": user + "@example.test", "login": user,
		"data": map[string]string{"id": sub, "name": user, "username": user},
	})
}

// accessToken accepts the Authorization header and, because some RPs send it
// that way (which /_audit/requests then records for RP-12), the query.
func accessToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.URL.Query().Get("access_token")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// randomDigits makes a 30-digit (about 99-bit) access token. Digits only, so
// clients that decode access_token as a JSON number (e.g. Go's json.Number)
// can read it too.
func randomDigits() string {
	b := make([]byte, 30)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = '0' + b[i]%10
	}
	b[0] = '1' + b[0]%9 // a JSON number may not start with 0
	return string(b)
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9400", "listen address; port 0 picks a free port")
	issuer := flag.String("issuer", "", "issuer URL (default http://<listen address>)")
	flag.Parse()
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	if *issuer == "" {
		*issuer = "http://" + l.Addr().String()
	}
	fmt.Println("fakeidp listening on http://" + l.Addr().String() + " issuer " + *issuer)
	log.Fatal(http.Serve(l, newServer(*issuer)))
}
