package usecase

import (
	"core-service/internal/delivery/rest"
	"errors"
)

type PostUseCase struct {
	authClient *rest.AuthClient
	// ... другие поля
}

func NewPostUseCase(authClient *rest.AuthClient) *PostUseCase {
	return &PostUseCase{
		authClient: authClient,
	}
}

func (uc *PostUseCase) CreatePost(token string, post *entity.Post) error {
	valid, err := uc.authClient.ValidateToken(token)
	if err != nil || !valid {
		return errors.New("unauthorized")
	}
	// ... остальная логика
}
