package utils

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path

		// disable auth as per array of strings value
		for _, value := range []string{} {
			if value == requestPath || strings.HasPrefix(requestPath, "/docs") {
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

		if tokenHeader == "" { //Token is missing, returns with error code Unauthorized
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Response(w, nil, CreateErrx(http.StatusForbidden, errors.New("Missing auth token"), MessageForbidden))
			return
		}

		splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
		if len(splitted) != 2 || splitted[0] != "Bearer" {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Response(w, nil, CreateErrx(http.StatusForbidden, errors.New("Invalid/Malformed auth token"), MessageForbidden))
			return
		}

		tokenPart := splitted[1] //Grab the token part, what we are truly interested in
		tk := &Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil { //Malformed token, returns with http code 400
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Response(w, nil, CreateErrx(http.StatusForbidden, errors.New("Malformed authentication token"), MessageForbidden))
			return
		}

		if !token.Valid { //Token is invalid, maybe not signed on this server
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Response(w, nil, CreateErrx(http.StatusUnauthorized, errors.New("Invalid token"), MessageStatusUnauthorized))
			return
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		tokenByte, err := json.Marshal(map[string]interface{}{
			"user_id": tk.Id,
			"email":   tk.Email,
		})
		ctx := context.WithValue(r.Context(), "token", tokenByte)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	})
}
