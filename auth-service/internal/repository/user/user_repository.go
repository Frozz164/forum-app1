package repository

import (
	"fmt"
	"forum-app/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
	_ "golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	FindByUsername(username string) (*domain.User, error)
	FindByID(id int) (*domain.User, error)
}

// InMemoryUserRepository (example)
type InMemoryUserRepository struct {
	users map[string]domain.User
}

func NewInMemoryUserRepository() UserRepository {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	return &InMemoryUserRepository{
		users: map[string]domain.User{
			"user1": {ID: 1, Username: "user1", Password: string(hashedPassword)},
			"user2": {ID: 2, Username: "user2", Password: string(hashedPassword)},
		},
	}
}

func (r *InMemoryUserRepository) FindByUsername(username string) (*domain.User, error) {
	user, ok := r.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

func (r *InMemoryUserRepository) FindByID(id int) (*domain.User, error) {
	for _, user := range r.users {
		if user.ID == id {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}
