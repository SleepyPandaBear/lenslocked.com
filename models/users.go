package models

import (
    "errors"
    "strings"
    "regexp"
    "time"

    "lenslocked.com/hash"
    "lenslocked.com/rand"

    "github.com/jinzhu/gorm"
    _ "github.com/jinzhu/gorm/dialects/postgres"
    "golang.org/x/crypto/bcrypt"
)

const (
    ErrNotFound modelError = "models: resource not found"
    ErrIDInvalid modelError = "models: ID provided was invalid"
    ErrPasswordIncorrect modelError = "models: incorrect password provided"
    ErrEmailRequired modelError = "models: email address is required"
    ErrEmailInvalid modelError = "models: email address is not valid"
    ErrEmailTaken modelError = "models: email address is already taken"
    ErrPasswordTooShort modelError = "models: password must be at least 8 characters long"
    ErrPasswordRequired modelError = "models: password is required"
    ErrRememberRequired modelError = "models: remember token is required"
    ErrRememberTokenTooShort modelError = "models: remeber token must be at least 32 bytes"
    ErrTokenInvalid modelError = "models: token provided is not valid"
)

type User struct {
    gorm.Model
    Name string
    Email string "gorm:\"not null; unique_index\""
    Password string "gorm:\"-\""
    PasswordHash string "gorm:\"not null\""
    Remember string "gorm:\"-\""
    RememberHash string "gorm:\"not null; unique_index\""
}

var _ UserDB = &userGorm{}
var _ UserService = &userService{}

type UserDB interface {
    ByID(id uint) (*User, error)
    ByEmail(email string) (*User, error)
    ByRemember(token string) (*User, error)

    Create(user *User) error
    Update(user *User) error
    Delete(id uint) error
}

type UserService interface {
    Authenticate(email, password string) (*User, error)
    InitiateReset(email string) (string, error)
    CompleteReset(token, newPw string) (*User, error)
    UserDB
}

type UserReader interface {
    ByID(id uint) (*User, error)
    ByRemember(token string) (*User, error)
}

type userGorm struct {
    db *gorm.DB
}

type userService struct {
    UserDB
    pepper string
    pwResetDB pwResetDB
}

type userValidator struct {
    UserDB
    hmac hash.HMAC
    emailRegex *regexp.Regexp
    pepper string 
}

type userCache struct {
    db *gorm.DB
}

func (ug userGorm) ByID(id uint) (*User, error) {
    var user User
    db := ug.db.Where("id = ?", id)
 
    err := first(db, &user)
    if err != nil {
        return nil, err
    }
    
    return &user, nil
}

func (uv *userValidator) ByID(id uint) (*User, error) {
    if id <= 0 {
        return nil, errors.New("Invalid ID")
    }

    return uv.UserDB.ByID(id)
}

func (ug userGorm) ByEmail(email string) (*User, error) {
    var user User
    db := ug.db.Where("email = ?", email)
    err := first(db, &user)
    if err != nil {
        return nil, err
    }
    
    return &user, err
}

func (ug *userGorm) ByRemember(rememberHash string) (*User, error) {
    var user User
    err := first(ug.db.Where("remember_hash = ?", rememberHash), &user)
    if err != nil {
        return nil, err 
    }

    return &user, nil
}

func (uv *userValidator) ByRemember(token string) (*User, error) {
    user := User{
        Remember: token,
    }

    if err := runUserValFns(&user, uv.hmacRemember); err != nil {
        return nil, err
    }

    return uv.UserDB.ByRemember(user.RememberHash)
}

func (ug userGorm) Create(user *User) error {
    return ug.db.Create(user).Error
}

func (uv *userValidator) Create(user *User) error {
    err := runUserValFns(user,
        uv.passwordRequired,
        uv.passwordMinLength,
        uv.bcryptPassword,
        uv.passwordHashRequired,
        uv.setRememberIfUnset,
        uv.rememberMinBytes,
        uv.hmacRemember,
        uv.rememberHashRequired,
        uv.normalizeEmail,
        uv.requireEmail,
        uv.emailFormat,
        uv.emailIsAvail)

    if err != nil  {
        return err
    }

    return uv.UserDB.Create(user)
}

func (ug userGorm) Update(user *User) error {
    return ug.db.Save(user).Error
}

func (uv *userValidator) Update(user *User) error {
    err := runUserValFns(user,
        uv.passwordMinLength,
        uv.bcryptPassword,
        uv.passwordHashRequired,
        uv.hmacRemember,
        uv.rememberHashRequired,
        uv.normalizeEmail,
        uv.requireEmail,
        uv.emailFormat,
        uv.emailIsAvail)

    if err != nil  {
        return err
    }

    return uv.UserDB.Update(user)
}

func (ug userGorm) Delete(id uint) error {
    user := User{Model: gorm.Model{ID: id}}
    return ug.db.Delete(&user).Error
}

func (uv *userValidator) Delete(id uint) error {
    var user User
    user.ID = id
    err := runUserValFns(&user, uv.idGreaterThan(0))

    if err != nil {
        return err
    }

    return uv.UserDB.Delete(id)
}

func newUserValidator(udb UserDB, hmac hash.HMAC, pepper string) *userValidator {
    return &userValidator{
        UserDB: udb,
        hmac: hmac,
        pepper: pepper,
        emailRegex: regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,16}$`),
    }
}

func first(db *gorm.DB, dst interface{}) error {
    err := db.First(dst).Error
    if err == gorm.ErrRecordNotFound {
        return ErrNotFound
    }

    return err
}

func NewUserService(db *gorm.DB, pepper, hmacKey string) UserService {
    ug := &userGorm{db}
    hmac := hash.NewHMAC(hmacKey)
    uv := newUserValidator(ug, hmac, pepper)
    return &userService{
        UserDB: uv,
        pepper: pepper,
        pwResetDB: newPwResetValidator(&pwResetGorm{db}, hmac),
    }
}

func (uv *userValidator) bcryptPassword(user *User) error {
    if user.Password == "" {
        return nil
    }

    pwBytes := []byte(user.Password + uv.pepper)
    hashedBytes, err := bcrypt.GenerateFromPassword(pwBytes, bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    user.PasswordHash = string(hashedBytes)
    user.Password = ""
    return nil
}

type userValFn func(*User) error

func (uv *userValidator) hmacRemember (user *User) error {
    if user.Remember == "" {
        return nil
    }

    user.RememberHash = uv.hmac.Hash(user.Remember)
    return nil
}

func (uv *userValidator) setRememberIfUnset(user *User) error {
    if user.Remember != "" {
        return nil
    }

    token, err := rand.RememberToken()
    if err != nil {
        return err
    }

    user.Remember = token
    return nil
}

func (uv *userValidator) normalizeEmail(user *User) error {
    user.Email = strings.ToLower(user.Email)
    user.Email = strings.TrimSpace(user.Email)
    return nil
}

func (uv *userValidator) ByEmail(email string) (*User, error) {
    user := User{
        Email: email,
    }

    err := runUserValFns(&user, uv.normalizeEmail)

    if err != nil {
        return nil, err
    }

    return uv.UserDB.ByEmail(user.Email)
}

func (uv *userValidator) idGreaterThan(n uint) userValFn {
    return userValFn(func(user *User) error {
        if user.ID <= n {
            return ErrIDInvalid
        }

        return nil
    })
}

func (uv *userValidator) requireEmail(user *User) error {
    if user.Email == "" {
        return ErrEmailRequired 
    }

    return nil
}

func (uv *userValidator) emailFormat(user *User) error {
    if user.Email == "" {
        return nil
    }
    if !uv.emailRegex.MatchString(user.Email) {
        return ErrEmailInvalid
    }

    return nil
}

func (uv *userValidator) emailIsAvail(user *User) error {
    existing, err := uv.ByEmail(user.Email)

    if err == ErrNotFound {
        return nil
    }

    if err != nil {
        return err
    }

    if user.ID != existing.ID {
        return ErrEmailTaken
    }

    return nil
}

func (uv *userValidator) passwordMinLength(user *User) error {
    if user.Password == "" {
        return nil
    }

    if len(user.Password) < 8 {
        return ErrPasswordTooShort
    }

    return nil
}

func (uv *userValidator) passwordRequired(user *User) error {
    if user.Password == "" {
        return ErrPasswordRequired
    }

    return nil
}

func (uv *userValidator) rememberMinBytes(user *User) error {
    if user.Remember == "" {
        return nil
    }

    n, err := rand.NBytes(user.Remember)
    if err != nil {
        return err
    }

    if n < 32 {
        return ErrRememberTokenTooShort
    }

    return nil
}

func (uv *userValidator) rememberHashRequired(user *User) error {
    if user.RememberHash == "" {
        return ErrRememberRequired
    }

    return nil
}

func (uv *userValidator) passwordHashRequired(user *User) error {
    if user.PasswordHash == "" {
        return ErrPasswordRequired
    }

    return nil
}

func runUserValFns(user *User, fns ...userValFn) error {
    for _, fn := range fns {
        if err := fn(user); err != nil {
            return err
        }
    }

    return nil
}

type modelError string

func (e modelError) Error() string {
    return string(e)
}

func (e modelError) Public() string {
    s := strings.Replace(string(e), "models: ", "", 1)
    split := strings.Split(s, " ")
    split[0] = strings.Title(split[0])
    return strings.Join(split, " ")
}

func (us *userService) Authenticate(email, password string) (*User, error) {
    foundUser, err := us.ByEmail(email)
    if err != nil {
        return nil, err
    }

    err = bcrypt.CompareHashAndPassword(
        []byte(foundUser.PasswordHash),
        []byte(password + us.pepper))

    switch err {
    case nil:
        return foundUser, nil
    case bcrypt.ErrMismatchedHashAndPassword:
        return nil, ErrPasswordIncorrect
    default:
        return nil, err
    }
}

func (us *userService) InitiateReset(email string) (string, error) {
    user, err := us.ByEmail(email)
    if err != nil {
        return "", err
    }

    pwr := pwReset{
        UserID: user.ID,
    }

    if err := us.pwResetDB.Create(&pwr); err != nil {
        return "", err
    }

    return pwr.Token, nil
}

func (us *userService) CompleteReset(token, newPw string) (*User, error) {
    pwr, err := us.pwResetDB.ByToken(token)
    if err != nil {
        if err == ErrNotFound {
            return nil, ErrTokenInvalid
        }
        return nil, err
    }

    if time.Now().Sub(pwr.CreatedAt) > (12 * time.Hour) {
        return nil, ErrTokenInvalid
    }

    user, err := us.ByID(pwr.UserID)
    if err != nil {
        return nil, err
    }

    user.Password = newPw
    err = us.Update(user)
    if err != nil {
        return nil, err
    }

    us.pwResetDB.Delete(pwr.ID)
    return user, nil
}
