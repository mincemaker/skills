package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func do(t *testing.T, s *server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" && !strings.HasPrefix(body, "{") {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// login runs /authorize and returns the code and the callback query.
func login(t *testing.T, s *server, extra string) (string, url.Values) {
	t.Helper()
	w := do(t, s, "GET", "/o/oauth2/v2/auth?client_id=c1&redirect_uri=https://app.example/callback&state=st&scope=openid&nonce=n1"+extra, "")
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	return loc.Query().Get("code"), loc.Query()
}

func exchange(t *testing.T, s *server, code, verifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://app.example/callback"}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	w := do(t, s, "POST", "/token", form.Encode())
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func TestFakeIDP(t *testing.T) {
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := "&code_challenge=" + base64.RawURLEncoding.EncodeToString(sum[:]) + "&code_challenge_method=S256"

	t.Run("pkce_and_single_use", func(t *testing.T) {
		s := newServer("https://idp.example")
		code, q := login(t, s, challenge)
		if q.Get("state") != "st" || q.Get("iss") != "" {
			t.Fatalf("callback query %v", q)
		}
		if st, _ := exchange(t, s, code, strings.Repeat("w", 43)); st != 400 {
			t.Fatalf("wrong verifier accepted: %d", st)
		}
		if st, _ := exchange(t, s, code, verifier); st != 200 {
			t.Fatalf("right verifier rejected: %d", st)
		}
		if st, _ := exchange(t, s, code, verifier); st != 400 {
			t.Fatalf("code reuse accepted: %d", st)
		}
	})

	t.Run("linkedin_style_paths", func(t *testing.T) {
		s := newServer("https://idp.example")
		w := do(t, s, "GET", "/oauth/v2/authorization?client_id=c1&redirect_uri=https://app.example/callback", "")
		if w.Code != http.StatusFound {
			t.Fatalf("authorization path: %d", w.Code)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		form := url.Values{"code": {loc.Query().Get("code")}}
		if w := do(t, s, "POST", "/oauth/v2/accessToken", form.Encode()); w.Code != 200 {
			t.Fatalf("accessToken path: %d %s", w.Code, w.Body)
		}
	})

	t.Run("downgrade_rejected", func(t *testing.T) {
		s := newServer("https://idp.example")
		code, _ := login(t, s, "")
		if st, _ := exchange(t, s, code, verifier); st != 400 {
			t.Fatalf("verifier without challenge accepted: %d", st)
		}
	})

	t.Run("id_token_signed_and_tampered", func(t *testing.T) {
		s := newServer("https://idp.example")
		code, _ := login(t, s, "&_user=attacker")
		_, m := exchange(t, s, code, "")
		parts := strings.Split(m["id_token"].(string), ".")
		var claims map[string]any
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(b, &claims)
		if claims["sub"] != "attacker" || claims["nonce"] != "n1" || claims["aud"] != "c1" || claims["iss"] != "https://idp.example" {
			t.Fatalf("claims %v", claims)
		}
		// verify with the published JWKS, as an RP would
		var jwks struct{ Keys []map[string]string }
		_ = json.Unmarshal(do(t, s, "GET", "/jwks", "").Body.Bytes(), &jwks)
		x, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0]["x"])
		y, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0]["y"])
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("signature does not verify against JWKS")
		}

		do(t, s, "POST", "/_audit/scenario", `{"alg":"none","id_token":{"aud":"other","nonce":null},"iss_override":"https://evil.example"}`)
		code, q := login(t, s, "")
		if q.Get("iss") != "https://evil.example" {
			t.Fatalf("iss override: %v", q)
		}
		_, m = exchange(t, s, code, "")
		parts = strings.Split(m["id_token"].(string), ".")
		b, _ = base64.RawURLEncoding.DecodeString(parts[1])
		claims = map[string]any{}
		_ = json.Unmarshal(b, &claims)
		head, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if parts[2] != "" || !strings.Contains(string(head), `"none"`) || claims["aud"] != "other" || claims["nonce"] != nil {
			t.Fatalf("tamper not applied: %s %v", head, claims)
		}
	})

	t.Run("userinfo_and_request_log", func(t *testing.T) {
		s := newServer("https://idp.example")
		code, _ := login(t, s, "")
		_, m := exchange(t, s, code, "")
		r := httptest.NewRequest("GET", "/oauth2/v2/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+m["access_token"].(string))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"victim"`) {
			t.Fatalf("userinfo %d %s", w.Code, w.Body)
		}
		for range 200 { // a leading 0 used to break json.Number about 1 in 10
			var n json.Number
			if err := json.Unmarshal([]byte(`"`+randomDigits()+`"`), &n); err != nil {
				t.Fatalf("access_token is not readable as json.Number: %v", err)
			}
		}
		// another API of the provider, token in the query
		w = do(t, s, "GET", "/photos/me?access_token="+m["access_token"].(string), "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"victim"`) {
			t.Fatalf("resource api %d %s", w.Code, w.Body)
		}
		var reqs []Request
		_ = json.Unmarshal(do(t, s, "GET", "/_audit/requests", "").Body.Bytes(), &reqs)
		if len(reqs) != 4 || reqs[1].Path != "/token" || !strings.Contains(reqs[1].Body, "code=") || reqs[3].Path != "/photos/me" || reqs[3].User != "victim" {
			t.Fatalf("request log %+v", reqs)
		}
	})
}
