package models

import (
    "github.com/jinzhu/gorm"
    _ "github.com/jinzhu/gorm/dialects/postgres"
)

// func NewServices(dialect, connectionInfo string) (*Services, error) {
//     db, err := gorm.Open(dialect, connectionInfo)
//     if err != nil {
//         return nil, err
//     }
// 
//     db.LogMode(true)
// 
//     return &Services{
//         User: NewUserService(db),
//         Gallery: NewGalleryService(db),
//         Image: NewImageService(),
//         db: db,
//     }, nil
// }

type Services struct {
    Gallery GalleryService
    User UserService
    Image ImageService
    db *gorm.DB
}

func (s *Services) Close() error {
    return s.db.Close()
}

func (s *Services) AutoMigrate() error {
    return s.db.AutoMigrate(&User{}, &Gallery{}, &pwReset{}).Error
}

func (s *Services) DestructiveReset() error {
    err := s.db.DropTableIfExists(&User{}, &Gallery{}, &pwReset{}).Error
    if err != nil {
        return err
    }

    return s.AutoMigrate()
}

type ServicesConfig func(*Services) error

func NewServices(cfgs ...ServicesConfig) (*Services, error) {
    var s Services

    for _, cfg := range cfgs {
        if err := cfg(&s); err != nil {
            return nil, err
        }
    }

    return &s, nil
}

func WithGorm(dialect, connectionInfo string) ServicesConfig {
    return func(s *Services) error {
        db, err := gorm.Open(dialect, connectionInfo)
        if err != nil {
            return err
        }
        s.db = db
        return nil
    }
}

func WithLogMode(mode bool) ServicesConfig {
    return func(s *Services) error {
        s.db.LogMode(mode)
        return nil
    }
}

func WithUser(pepper, hmacKey string) ServicesConfig {
    return func(s *Services) error {
        s.User = NewUserService(s.db, pepper, hmacKey)
        return nil
    }
}

func WithGallery() ServicesConfig {
    return func(s *Services) error {
        s.Gallery = NewGalleryService(s.db)
        return nil
    }
}

func WithImage() ServicesConfig {
    return func(s *Services) error {
        s.Image = NewImageService()
        return nil
    }
}
