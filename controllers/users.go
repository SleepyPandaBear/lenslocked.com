package controllers

import (
    "fmt"
    "net/http"
    "time"
    "lenslocked.com/rand"
    "lenslocked.com/models"
    "lenslocked.com/views"
    "lenslocked.com/context"
)

type Users struct {
    NewView *views.View
    LoginView *views.View
    ForgotPwView *views.View
    ResetPwView *views.View
    us models.UserService
}

type SignupForm struct {
    Name string "schema:\"name\""
    Email string "schema:\"email\""
    Password string "schema:\"password\""
}

type LoginForm struct {
    Email string "schema:\"email\""
    Password string "schema:\"password\""
}

type ResetPwForm struct {
    Email string "schema:\"email\""
    Token string "schema:\"token\""
    Password string "schema:\"password\""
}

func NewUsers(us models.UserService) *Users {
    return &Users {
        NewView: views.NewView("bootstrap", "users/new"),
        LoginView: views.NewView("bootstrap", "users/login"),
        ForgotPwView: views.NewView("bootstrap", "users/forgot_pw"),
        ResetPwView: views.NewView("bootstrap", "users/reset_pw"),
        us: us,
    }
}

// GET /signup
func (u *Users) New(w http.ResponseWriter, r *http.Request) {
    var form SignupForm
    parseURLParams(r, &form)
    u.NewView.Render(w, r, form)
}

// POST /signup
func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
    var form SignupForm
    var vd views.Data
    vd.Yield = &form

    if err := parseForm(r, &form); err != nil {
        vd.SetAlert(err)
        u.NewView.Render(w, r, vd)
        return
    }

    user := models.User{
        Name: form.Name,
        Email: form.Email,
        Password: form.Password,
    }

    if err := u.us.Create(&user); err != nil {
        vd.SetAlert(err)
        u.NewView.Render(w, r, vd)
        return
    }

    err := u.signIn(w, &user)
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    http.Redirect(w, r, "/galleries", http.StatusFound)
}

// POST /login
func (u *Users) Login(w http.ResponseWriter, r *http.Request) {
    var vd views.Data
    var form LoginForm

    if err := parseForm(r, &form); err != nil {
        vd.SetAlert(err)
        u.LoginView.Render(w, r, vd)
        return
    }

    user, err := u.us.Authenticate(form.Email, form.Password)

    if err != nil {
        switch err {
        case models.ErrNotFound:
            vd.AlertError("no user exists with that email address")
        default:
            vd.SetAlert(err)
        }

        u.LoginView.Render(w, r, vd)
        return
    }

    // cookie := http.Cookie{
    //     Name: "email",
    //     Value: user.Email,
    // }

    // http.SetCookie(w, &cookie)

    // fmt.Fprintln(w, user)

    err = u.signIn(w, user)
    if err != nil {
        vd.SetAlert(err)
        u.LoginView.Render(w, r, vd)
        return
    }

    http.Redirect(w, r, "/galleries", http.StatusFound)
}

func (u *Users) CookieTest(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("remember_token")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    user, err := u.us.ByRemember(cookie.Value)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, user)
}

func (u *Users) signIn(w http.ResponseWriter, user *models.User) error {
    if user.Remember == "" {
        token, err := rand.RememberToken()
        if err != nil {
            return err
        }

        user.Remember = token
        err = u.us.Update(user)
        if err != nil {
            return err
        }
    }

    cookie := http.Cookie{
        Name: "remember_token",
        Value: user.Remember,
        HttpOnly: true,
    }

    http.SetCookie(w, &cookie)
    return nil
}

// POST /logout
func (u *Users) Logout(w http.ResponseWriter, r *http.Request) {
    cookie := http.Cookie{
        Name: "remember_token",
        Value: "",
        Expires: time.Now(),
        HttpOnly: true,
    }
    
    http.SetCookie(w, &cookie)
    user := context.User(r.Context())
    token, _ := rand.RememberToken()
    user.Remember = token
    u.us.Update(user)
    http.Redirect(w, r, "/", http.StatusFound)
}

// POST /forgot
func (u *Users) InitiateReset(w http.ResponseWriter, r *http.Request) {
    var vd views.Data
    var form ResetPwForm
    vd.Yield = form
    if err := parseForm(r, &form); err != nil {
        vd.SetAlert(err)
        u.ForgotPwView.Render(w, r, vd)
        return
    }

    token, err := u.us.InitiateReset(form.Email)
    if err != nil {
        vd.SetAlert(err)
        u.ForgotPwView.Render(w, r, vd)
        return
    }

    _ = token

    views.RedirectAlert(w, r, "/reset", http.StatusFound, views.Alert{
        Level: views.AlertLvlSuccess,
        Message: "Instructions for resseting your password have been emaild to you",
    })
}

// GET /reset
func (u *Users) ResetPw(w http.ResponseWriter, r *http.Request) {
    var vd views.Data
    var form ResetPwForm
    vd.Yield = &form
    if err := parseURLParams(r, &form); err != nil {
        vd.SetAlert(err)
    }

    u.ResetPwView.Render(w, r, vd)
}

// POST /reset
func (u *Users) CompleteReset(w http.ResponseWriter, r *http.Request) {
    var vd views.Data
    var form ResetPwForm
    vd.Yield = &form
    if err := parseForm(r, &form); err != nil {
        vd.SetAlert(err)
        u.ResetPwView.Render(w, r, vd)
        return
    }

    user, err := u.us.CompleteReset(form.Token, form.Password)
    if err != nil {
        vd.SetAlert(err)
        u.ResetPwView.Render(w, r, vd)
        return
    }

    u.signIn(w, user)
    views.RedirectAlert(w, r, "/galleries", http.StatusFound, views.Alert{
        Level: views.AlertLvlSuccess,
        Message: "your pw has been reset and you have been logged in",
    })
}
