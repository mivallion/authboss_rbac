package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/volatiletech/authboss/v3"
	_ "github.com/volatiletech/authboss/v3/auth"
	"github.com/volatiletech/authboss/v3/defaults"
	_ "github.com/volatiletech/authboss/v3/logout"
	_ "github.com/volatiletech/authboss/v3/register"
	"github.com/volatiletech/authboss/v3/remember"

	abclientstate "github.com/volatiletech/authboss-clientstate"

	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
)

var (
	ab       = authboss.New()
	database = NewMemStorer()

	sessionStore abclientstate.SessionStorer
	cookieStore  abclientstate.CookieStorer
)

const (
	sessionCookieName = "ab_rbac"
)

func setupAuthboss() {
	ab.Config.Paths.RootURL = "http://localhost:3000"
	ab.Config.Modules.LogoutMethod = "GET"
	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	// ab.Config.Core.ViewRenderer = abrenderer.NewHTML("/auth", "")
	ab.Config.Core.ViewRenderer = defaults.JSONRenderer{}
	ab.Config.Modules.RegisterPreserveFields = []string{"email"}

	defaults.SetCore(&ab.Config, false, false)

	emailRule := defaults.Rules{
		FieldName: "email", Required: true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]+`),
	}
	passwordRule := defaults.Rules{
		FieldName: "password", Required: true,
		MinLength: 4,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		Rulesets: map[string][]defaults.Rules{
			"register":    {emailRule, passwordRule},
			"recover_end": {passwordRule},
		},
		Confirms: map[string][]string{
			"register": {"password", authboss.ConfirmPrefix + "password"},
		},
		Whitelist: map[string][]string{
			"register": {"email", "name", "password"},
		},
	}

	// Initialize authboss (instantiate modules etc.)
	if err := ab.Init(); err != nil {
		panic(err)
	}
}

func main() {

	cookieStoreKey, _ := base64.StdEncoding.DecodeString(`NpEPi8pEjKVjLGJ6kYCS+VTCzi6BUuDzU0wrwXyf5uDPArtlofn2AG6aTMiPmN3C909rsEWMNqJqhIVPGP3Exg==`)
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(`AbfYwmmt8UCwUuhd9qvfNA9UCuN1cVcKJN1ofbiky6xCyyBj20whe40rJa3Su0WOWLWcPpO1taqJdsEI/65+JA==`)
	cookieStore = abclientstate.NewCookieStorer(cookieStoreKey, nil)
	cookieStore.HTTPOnly = false
	cookieStore.Secure = false
	sessionStore = abclientstate.NewSessionStorer(sessionCookieName, sessionStoreKey, nil)
	cstore := sessionStore.Store.(*sessions.CookieStore)
	cstore.Options.HttpOnly = false
	cstore.Options.Secure = false
	cstore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	setupAuthboss()

	mux := chi.NewRouter()

	mux.Use(logger, ab.LoadClientStateMiddleware, remember.Middleware(ab))

	// Authed routes
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.Middleware2(ab, authboss.RequireNone, authboss.RespondUnauthorized))
		mux.MethodFunc("GET", "/foo", foo)
		mux.MethodFunc("GET", "/bar", bar)
		mux.MethodFunc("GET", "/sigma", sigma)
	})

	// Routes
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.ModuleListMiddleware(ab))
		mux.Mount("/auth", http.StripPrefix("/auth", ab.Config.Core.Router))
	})
	mux.MethodFunc("GET", "/", ok)
	// Start the server
	port := "3000"
	log.Printf("Listening on localhost: %s", port)
	log.Println(http.ListenAndServe("localhost:"+port, mux))
}

func ok(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func foo(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("foo"))
}

func bar(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("bar"))
}

func sigma(w http.ResponseWriter, r *http.Request) {
	abuser := ab.CurrentUserP(r)
	user := abuser.(*User)
	if user.Role == "admin" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("sigma"))
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}
