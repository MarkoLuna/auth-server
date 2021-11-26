package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"com.github/MarkoLuna/oauthserver/pkg/dto"
	"com.github/MarkoLuna/oauthserver/pkg/utils"
	"github.com/golang-jwt/jwt"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
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

	clientId := utils.GetEnv("OAUTH_CLIENT_ID", "c6cece53")
	clientSecret := utils.GetEnv("OAUTH_CLIENT_SECRET", "f105afff")
	userId := utils.GetEnv("OAUTH_USER_ID", "000000")

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {

		clientIdReq, err := getSingleRequestParam(r, "client_id")
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Invalid client id", http.StatusUnauthorized)
			return
		}

		clientSecretReq, err := getSingleRequestParam(r, "client_secret")
		if err != nil {
			log.Println(err.Error())
			http.Error(w, "Invalid client secret", http.StatusUnauthorized)
			return
		}

		if clientId != clientIdReq {
			http.Error(w, "Invalid client id", http.StatusUnauthorized)
			return
		}

		if clientSecret != clientSecretReq {
			http.Error(w, "Invalid client secret", http.StatusUnauthorized)
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

		gen := generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512)
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
			return []byte("00000000"), nil
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
			return []byte("00000000"), nil
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

func getSingleRequestParam(r *http.Request, paramName string) (string, error) {
	params, ok := r.URL.Query()[paramName]

	if !ok || len(params[0]) < 1 {
		return "", errors.New("Url Param '" + paramName + "' is missing")
	}

	return string(params[0]), nil
}

func GetBearerAuth(r *http.Request) (string, bool) {
	return GetAuth(r, "Bearer ")
}

func GetAuth(r *http.Request, prefix string) (string, bool) {
	auth := r.Header.Get("Authorization")
	token := ""

	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	}

	return token, token != ""
}
