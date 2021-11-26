package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MarkoLuna/oauthserver/pkg/dto"
	"github.com/MarkoLuna/oauthserver/pkg/utils"
	"github.com/golang-jwt/jwt"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)

var (
	signingKey   = utils.GetEnv("OAUTH_SIGNING_KEY", "00000000")
	clientId     = utils.GetEnv("OAUTH_CLIENT_ID", "c6cece53")
	clientSecret = utils.GetEnv("OAUTH_CLIENT_SECRET", "f105afff")

	userId       = utils.GetEnv("OAUTH_USER_ID", "000000")
	userName     = utils.GetEnv("OAUTH_USER_NAME", "user")
	userPassword = utils.GetEnv("OAUTH_USER_PASSWORD", "secret")
)

func main() {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {

		auth, ok := GetBasicAuth(r)
		if !ok {
			http.Error(w, "Unable to find the Authentication", http.StatusUnauthorized)
			return
		}

		clientIdReq, clientSecretReq := DecodeBasicAuth(auth)
		validClientCred, err := IsValidClientCredentials(clientIdReq, clientSecretReq)
		if !validClientCred || err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		r.ParseForm()
		userNameReq := r.FormValue("username")
		passwordReq := r.FormValue("password")

		userValid, err := IsValidUser(userNameReq, passwordReq)
		if !userValid || err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		data := &oauth2.GenerateBasic{
			Client: &models.Client{
				ID:     clientId,
				Secret: clientSecret,
			},
			UserID: userId,
			TokenInfo: &models.Token{
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 120,
			},
		}

		gen := generates.NewJWTAccessGenerate("", []byte(signingKey), jwt.SigningMethodHS512)
		access, refresh, err := gen.Token(context.Background(), data, true)

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		jWTResponse := dto.JWTResponse{
			AccessToken:  access,
			RefreshToken: refresh,
			ExpiresIn:    int64(120), // 2 min
			Scope:        "all",
			TokenType:    "Bearer",
		}

		res, _ := json.Marshal(jWTResponse)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(res)
	})

	http.HandleFunc("/getClaims", func(w http.ResponseWriter, r *http.Request) {

		accessToken, ok := GetBearerAuth(r)
		if !ok {
			http.Error(w, "Unable to find the Authentication Token", http.StatusUnauthorized)
			return
		}

		// Parse and verify jwt access token
		token, err := jwt.ParseWithClaims(accessToken, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("parse error")
			}
			return []byte(signingKey), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*generates.JWTAccessClaims)
		if !ok || !token.Valid {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		dataMap := make(map[string]string)
		dataMap["subject"] = claims.Subject
		dataMap["audience"] = claims.Audience
		dataMap["id"] = claims.Id
		dataMap["issuer"] = claims.Issuer

		res, _ := json.Marshal(dataMap)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(res)
	})

	http.HandleFunc("/protected", validateToken(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, I'm protected"))
	}, srv))

	address := Address()

	log.Println("Starting server on:", address)
	log.Fatal(http.ListenAndServe(address, nil))
}

func Address() string {
	port := utils.GetEnv("SERVER_PORT", "9096")
	host := utils.GetEnv("SERVER_HOST", "0.0.0.0")

	return host + ":" + port
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		accessToken, ok := GetBearerAuth(r)
		if !ok {
			http.Error(w, "Unable to find the Authentication Token", http.StatusUnauthorized)
			return
		}

		// Parse and verify jwt access token
		token, err := jwt.ParseWithClaims(accessToken, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("parse error")
			}
			return []byte(signingKey), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		_, ok2 := token.Claims.(*generates.JWTAccessClaims)
		if !ok2 || !token.Valid {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		f.ServeHTTP(w, r)
	})
}

func IsValidUser(userNameReq string, passwordReq string) (bool, error) {
	if userName != userNameReq {
		return false, errors.New("Invalid username")
	}

	if userPassword != passwordReq {
		return false, errors.New("Invalid password")
	}

	return true, nil
}

func IsValidClientCredentials(client string, password string) (bool, error) {

	if clientId != client {
		return false, errors.New("Invalid client id")
	}

	if clientSecret != password {
		return false, errors.New("Invalid client secret")
	}

	return true, nil
}

func DecodeBasicAuth(auth string) (string, string) {
	authDecoded, _ := base64.StdEncoding.DecodeString(auth)
	authReq := strings.Split(string(authDecoded), ":")

	return authReq[0], authReq[1]
}

func GetBearerAuth(r *http.Request) (string, bool) {
	return GetAuthHeader(r, "Bearer ")
}

func GetBasicAuth(r *http.Request) (string, bool) {
	return GetAuthHeader(r, "Basic ")
}

func GetAuthHeader(r *http.Request, prefix string) (string, bool) {
	auth := r.Header.Get("Authorization")
	token := ""

	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	}

	return token, token != ""
}
