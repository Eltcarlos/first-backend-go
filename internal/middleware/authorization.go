package middleware

import (
	"errors"
	"net/http"

	"github.com/goapi/api"
	"github.com/goapi/internal/tools"
	log "github.com/sirupsen/logrus"
)

var UnAuthorizedError = errors.New("Invalid username or token.")

func Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract username and token from the request
		var username string = r.URL.Query().Get("username")
		var token = r.Header.Get("Authorization")
		var err error

		// Check for missing username or token
		if username == "" || token == "" {
			log.Error(UnAuthorizedError)
			api.RequestErrorHandler(w, UnAuthorizedError)
			return
		}

		// Initialize the database connection
		var database *tools.DatabaseInterface
		database, err = tools.NewDatabase()
		if err != nil {
			api.InternalErrorHandler(w)
			return
		}

		// Dereference the database pointer and retrieve login details
		var loginDetails *tools.LoginDetails
		loginDetails = (*database).GetUserLoginDetails(username)

		// Check if login details are missing or the token is invalid
		if loginDetails == nil || token != loginDetails.AuthToken {
			log.Error(UnAuthorizedError)
			api.RequestErrorHandler(w, UnAuthorizedError)
			return
		}

		// Call the next handler if authorization is successful
		next.ServeHTTP(w, r)
	})
}
