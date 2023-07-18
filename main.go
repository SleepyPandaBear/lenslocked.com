package main

import (
    "fmt"
    "net/http"
    "flag"

    "lenslocked.com/controllers"
    "lenslocked.com/rand"
    "lenslocked.com/models"
    "lenslocked.com/middleware"

    "github.com/gorilla/mux"
    "github.com/gorilla/csrf"
)

const (
    host = "localhost"
    port = 5432
    user = "postgres"
    password = "root"
    dbname = "lenslocked_dev"
)

func must(err error) {
    if err != nil {
        panic(err)
    }
}

func notFound(w http.ResponseWriter, r *http.Request) {
    fmt.Fprint(w, "custom 404")
}

func main() {
    var custom404 http.Handler = http.HandlerFunc(notFound)

    // boolPtr := flag.Bool("prod", false, "provide this flag in production")
    flag.Parse()

    cfg := LoadConfig(false)
    dbCfg := cfg.Database

    services, err := models.NewServices(
        models.WithGorm(dbCfg.Dialect(), dbCfg.ConnectionInfo()),
        models.WithLogMode(!cfg.IsProd()),
        models.WithUser(cfg.Pepper, cfg.HMACKey),
        models.WithGallery(),
        models.WithImage(),
    )
    if err != nil {
        panic(err)
    }

    defer services.Close()

    services.AutoMigrate()
    // services.DestructiveReset()

    r := mux.NewRouter()

    staticC := controllers.NewStatic()
    usersC := controllers.NewUsers(services.User)
    galleriesC := controllers.NewGalleries(services.Gallery, services.Image, r)

    userMw := middleware.User{
        UserService: services.User,
    }

    requireUserMw := middleware.RequireUser{}

    newGallery := requireUserMw.Apply(galleriesC.New)
    createGallery := requireUserMw.ApplyFn(galleriesC.Create)

    imageHandler := http.FileServer(http.Dir("./images/"))
    r.PathPrefix("/images/").Handler(http.StripPrefix("/images/", imageHandler))
    assetHandler := http.FileServer(http.Dir("./assets/"))
    r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", assetHandler))

    r.Handle("/", staticC.Home).Methods("GET")
    r.Handle("/contact", staticC.Contact).Methods("GET")
    r.HandleFunc("/signup", usersC.New).Methods("GET")
    r.HandleFunc("/signup", usersC.Create).Methods("POST")
    r.Handle("/login", usersC.LoginView).Methods("GET")
    r.HandleFunc("/login", usersC.Login).Methods("POST")
    r.HandleFunc("/cookietest", usersC.CookieTest).Methods("GET")
    r.Handle("/galleries/new", newGallery).Methods("GET")
    r.Handle("/galleries", requireUserMw.ApplyFn(galleriesC.Index)).
        Methods("GET").Name(controllers.IndexGalleries)
    r.HandleFunc("/galleries", createGallery).Methods("POST")
    r.HandleFunc("/galleries/{id:[0-9]+}", galleriesC.Show).
        Methods("GET").Name(controllers.ShowGallery)
    r.HandleFunc("/galleries/{id:[0-9]+}/edit", 
        requireUserMw.ApplyFn(galleriesC.Edit)).Methods("GET").
        Name(controllers.EditGallery)
    r.HandleFunc("/galleries/{id:[0-9]+}/update", 
        requireUserMw.ApplyFn(galleriesC.Update)).Methods("POST")
    r.HandleFunc("/galleries/{id:[0-9]+}/delete", 
        requireUserMw.ApplyFn(galleriesC.Delete)).Methods("POST")
    r.HandleFunc("/galleries/{id:[0-9]+}/images",
        requireUserMw.ApplyFn(galleriesC.ImageUpload)).Methods("POST")
    r.HandleFunc("/galleries/{id:[0-9]+}/images/{filename}/delete",
        requireUserMw.ApplyFn(galleriesC.ImageDelete)).Methods("POST")
    r.Handle("/logout", requireUserMw.ApplyFn(usersC.Logout)).Methods("POST")
    r.Handle("/forgot", usersC.ForgotPwView).Methods("GET")
    r.HandleFunc("/forgot", usersC.InitiateReset).Methods("POST")
    r.HandleFunc("/reset", usersC.ResetPw).Methods("GET")
    r.HandleFunc("/reset", usersC.CompleteReset).Methods("POST")

    b, err := rand.Bytes(32)
    if err != nil {
        panic(err)
    }
    csrfMw := csrf.Protect(b, csrf.Secure(cfg.IsProd()))

    r.NotFoundHandler = custom404
    http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), csrfMw(userMw.Apply(r)))
}
