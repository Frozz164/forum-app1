package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"forum-app/auth-service/internal/config"
	"forum-app/auth-service/internal/domain"
	"forum-app/auth-service/internal/repository"
	userRepository "forum-app/auth-service/internal/repository/user"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Login(ctx context.Context, username, password string) (*domain.TokenDetails, error)
	RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenDetails, error)
	VerifyAccessToken(tokenString string) (*domain.AccessDetails, error)
	GenerateTokens(user *domain.User) (*domain.TokenDetails, error)
	CreateRefreshToken(userID int) (string, error)
}

type AuthServiceImpl struct {
	userRepository   userRepository.UserRepository
	keyRepository    repository.KeyRepository
	refreshTokenRepo repository.RefreshTokenRepository
	config           *config.Config
}

func NewAuthService(userRepo userRepository.UserRepository, keyRepo repository.KeyRepository, refreshTokenRepo repository.RefreshTokenRepository, cfg *config.Config) AuthService {
	return &AuthServiceImpl{
		userRepository:   userRepo,
		keyRepository:    keyRepo,
		refreshTokenRepo: refreshTokenRepo,
		config:           cfg,
	}
}

func (s *AuthServiceImpl) Login(ctx context.Context, username, password string) (*domain.TokenDetails, error) {
	user, err := s.userRepository.FindByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	tokens, err := s.GenerateTokens(user)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (s *AuthServiceImpl) GenerateTokens(user *domain.User) (*domain.TokenDetails, error) {
	td := &domain.TokenDetails{}
	td.AtExpires = time.Now().Add(s.config.AccessTokenTTL)
	td.AccessUuid = uuid.New().String()

	td.RtExpires = time.Now().Add(s.config.RefreshTokenTTL)
	td.RefreshUuid = uuid.New().String()

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = user.ID
	atClaims["exp"] = td.AtExpires.Unix()
	accessKey, err := s.keyRepository.GetCurrentKey()
	if err != nil {
		return nil, err
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(accessKey))
	if err != nil {
		return nil, err
	}

	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = user.ID
	rtClaims["exp"] = td.RtExpires.Unix()

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(s.config.JWTSigningKey))
	if err != nil {
		return nil, err
	}

	// Store refresh token in MongoDB
	refreshToken := &domain.RefreshToken{
		ID:        td.RefreshUuid,
		UserID:    user.ID,
		Token:     td.RefreshToken,
		ExpiresAt: td.RtExpires,
		CreatedAt: time.Now(),
	}

	err = s.refreshTokenRepo.Create(context.Background(), refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}
	return td, nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenDetails, error) {
	//Verify the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSigningKey), nil
	})
	if err != nil {
		return nil, err
	}

	//Is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return nil, err
	}

	//Since token is valid, get the claims
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {

		//Get the user id from the token claims
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			return nil, err
		}

		userID, err := s.extractRefreshTokenMetadata(refreshToken)
		if err != nil {
			return nil, err
		}

		// Lookup refresh token in MongoDB
		storedRefreshToken, err := s.refreshTokenRepo.Get(context.Background(), refreshToken)
		if err != nil {
			return nil, fmt.Errorf("invalid refresh token: %w", err)
		}

		if storedRefreshToken.ID != refreshUuid {
			return nil, fmt.Errorf("invalid refresh token uuid")
		}

		// Delete the old refresh token
		err = s.refreshTokenRepo.Delete(context.Background(), refreshToken)
		if err != nil {
			log.Printf("Failed to delete refresh token: %v", err)
		}

		//Get the user details from the User id
		user, err := s.userRepository.FindByID(userID)
		if err != nil {
			return nil, err
		}

		//Generate new tokens
		ts, err := s.GenerateTokens(user)
		if err != nil {
			return nil, err
		}
		return ts, nil
	} else {
		return nil, err
	}
}

func (s *AuthServiceImpl) extractRefreshTokenMetadata(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSigningKey), nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userID, ok := claims["user_id"].(float64)
		if !ok {
			return 0, err
		}
		return int(userID), nil
	}
	return 0, err
}

func (s *AuthServiceImpl) VerifyAccessToken(tokenString string) (*domain.AccessDetails, error) {
	accessKey, err := s.keyRepository.GetCurrentKey()
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(accessKey), nil
	})
	if err != nil {
		return nil, err
	}
	//Is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := s.extractTokenMetadata(tokenString)
		if err != nil {
			return nil, err
		}

		return &domain.AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}

func (s *AuthServiceImpl) extractTokenMetadata(tokenString string) (int, error) {
	accessKey, err := s.keyRepository.GetCurrentKey()
	if err != nil {
		return 0, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(accessKey), nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userID, ok := claims["user_id"].(float64)
		if !ok {
			return 0, err
		}
		return int(userID), nil
	}
	return 0, err
}

func (s *AuthServiceImpl) CreateRefreshToken(userID int) (string, error) {
	refreshToken := uuid.New().String()

	// Сохраните refresh token в MongoDB с UserID и временем истечения срока действия.

	return refreshToken, nil
}
