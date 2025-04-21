package handlers

import (
	"context"
	"fmt"
	"forum-app/auth-service/internal/repository"
	"log"
	"net/http"
	"time"

	"forum-app/auth-service/internal/domain"
	"forum-app/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService services.AuthService
}

func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.authService.Login(context.Background(), req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.authService.RefreshToken(context.Background(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// Middleware для проверки access token
func (h *AuthHandler) AuthMiddleware(authService services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		//  Предполагается, что формат "Bearer <token>"
		tokenString := authHeader[7:] // Remove "Bearer "

		accessDetails, err := authService.VerifyAccessToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
			return
		}

		c.Set("access_details", accessDetails)
		c.Next()
	}
}

func (h *AuthHandler) Protected(c *gin.Context) {
	accessDetails, exists := c.Get("access_details")
	if !exists {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve access details"})
		return
	}

	// Assert the type of accessDetails to *domain.AccessDetails
	accessDetailsPtr, ok := accessDetails.(*domain.AccessDetails)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid access details format"})
		return
	}

	// Access the fields of the *domain.AccessDetails struct
	c.JSON(http.StatusOK, gin.H{"message": "Protected resource accessed successfully", "user_id": accessDetailsPtr.UserId})
}

// Пример: получить ID пользователя из контекста
func GetUserID(c *gin.Context) (int, error) {
	accessDetails, exists := c.Get("access_details")
	if !exists {
		return 0, fmt.Errorf("access details not found in context")
	}

	accessDetailsPtr, ok := accessDetails.(*domain.AccessDetails)
	if !ok {
		return 0, fmt.Errorf("invalid access details format")
	}

	return accessDetailsPtr.UserId, nil
}

func SetupAuthRoutes(router *gin.Engine, authService services.AuthService) {
	handler := NewAuthHandler(authService)
	router.POST("/login", handler.Login)
	router.POST("/refresh", handler.Refresh)

	// Protected routes
	protected := router.Group("/protected")
	protected.Use(handler.AuthMiddleware(authService))
	{
		protected.GET("/resource", handler.Protected)
	}
}

// Функция для периодической ротации ключей
func RotateKeysPeriodically(keyRepository repository.KeyRepository, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		_, err := keyRepository.RotateKey()
		if err != nil {
			log.Printf("Error rotating key: %v", err)
		}
	}
}
