package utils

import (
	"errors"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// var db *sqlx.DB

type (
	Token struct {
		UserID int64
		Email  string
		jwt.StandardClaims
	}
	Errorx struct {
		Err     error
		Status  uint
		Message string
	}
)

const (
	MessageInternalServerError = "Internal server error"
	MessageBadRequest          = "Kindly check you request"
	MessageNotFound            = "Not Found"
	MessageForbidden           = "Forbidden access"
	MessageStatusUnauthorized  = "Unauthorized Access"
)

var (
	ErrorInvalidEmail = Errorx{
		Err:     errors.New("Email is Invalid"),
		Message: "Your Email is Invalid",
		Status:  http.StatusUnprocessableEntity,
	}
	ErrorInvalidPassword = Errorx{
		Err:     errors.New("Password is Invalid"),
		Message: "Your Password is Invalid, min 6 digits and max 20 digits",
		Status:  http.StatusUnprocessableEntity,
	}
	ErrorInvalidCredential = Errorx{
		Err:     errors.New("Invalid Credential"),
		Message: "Invalid e-mail or password",
		Status:  http.StatusNotFound,
	}
)

// CreateErrx is a func to create errorx
func CreateErrx(status uint, err error, message string) Errorx {
	if status <= 0 || status >= 600 {
		status = http.StatusInternalServerError
	}
	if len(message) > 0 {
		log.Println(message)
	}
	return Errorx{
		Status:  status,
		Err:     err,
		Message: message,
	}
}
