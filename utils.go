package utils

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
)

// Message function is to build response per standard
func Message(errx Errorx, data interface{}) (res map[string]interface{}) {
	res = map[string]interface{}{
		"status":  errx.Status,
		"message": errx.Message,
	}
	if data != nil {
		res["data"] = data
	}
	if errx.Err != nil {
		res["internalMessage"] = errx.Err.Error()
	}
	return res
}

// Response function is to encode response
func Response(w http.ResponseWriter, data interface{}, errx Errorx) {
	w.Header().Add("Content-Type", "application/json")
	if errx.Err != nil {
		json.NewEncoder(w).Encode(Message(errx, data))
	} else {
		json.NewEncoder(w).Encode(Message(Errorx{
			Message: "Success",
			Status:  http.StatusOK,
		}, data))
	}
}

// HashPassword function is to hash string
func HashPassword(value string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), err
}

// CreateJWT function is to get token based on Token data
func CreateJWT(value Token) (res string, err error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), value)
	return token.SignedString([]byte(os.Getenv("token_password")))
}

// IsNil is nil value ?
func IsNil(value interface{}) (res bool) {
	return (value == nil || (reflect.TypeOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil()))
}

// ToString to casting interface to string
func ToString(value interface{}) (res string) {
	if !IsNil(value) {
		val := reflect.ValueOf(value)
		switch val.Kind() {
		case reflect.String:
			res = val.String()

		case reflect.Ptr:
			res = ToString(reflect.Indirect(val))

		default:
			byt, err := json.Marshal(value)
			if err == nil {
				res = string(byt)
			}
		}
	}
	return
}

// ToInt to casting interface to int64
func ToInt(value interface{}, def int64) int64 {
	r, err := strconv.ParseInt(ToString(value), 10, 64)
	if err != nil {
		r = def
	}
	return r
}

// StringToInt to casting string to integer
func StringToInt(value string, def int64) int64 {
	r, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		r = def
	}
	return r
}

// ReadFromToken is a function to read data from jwt with *http.Request as its param
func ReadFromToken(r *http.Request) (result *Token, err error) {
	err = json.Unmarshal([]byte(r.Context().Value("token").(string)), result)
	if err != nil || result.UserID <= 0 || !govalidator.IsEmail(strings.TrimSpace(result.Email)) {
		return nil, errors.New("Invalid Token")
	}
	return result, nil
}
