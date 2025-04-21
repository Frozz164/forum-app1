package internal

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"forum-app/auth-service/internal/config"
	"forum-app/auth-service/internal/handlers"
	"forum-app/auth-service/internal/repository"
	userRepository "forum-app/auth-service/internal/repository/user"
	"forum-app/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

func Run() error {
	cfg := config.LoadConfig()

	// Initialize SQLite Key Repository
	keyRepo, err := repository.NewSQLiteKeyRepository(cfg.SQLitePath)
	if err != nil {
		return err
	}

	// Initialize MongoDB Refresh Token Repository
	refreshTokenRepo, err := repository.NewMongoDBRefreshTokenRepository(cfg.MongoDBURI, cfg.MongoDBName)
	if err != nil {
		return err
	}
	defer func() {
		if rRepo, ok := refreshTokenRepo.(*repository.MongoDBRefreshTokenRepository); ok {
			rRepo.CloseMongoDBConnection()
		}
	}()

	// Initialize User Repository (example in-memory)
	userRepo := userRepository.NewInMemoryUserRepository()

	// Initialize Auth Service
	authService := services.NewAuthService(userRepo, keyRepo, refreshTokenRepo, cfg)

	// Initialize Gin Router
	router := gin.Default()

	// Setup Auth Routes
	handlers.SetupAuthRoutes(router, authService)

	// Start Key Rotation in the Background
	go handlers.RotateKeysPeriodically(keyRepo, time.Minute*15)

	// Server setup
	server := &http.Server{
		Addr:    cfg.Port,
		Handler: router,
	}

	// Graceful shutdown
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Fatal("Server shutdown:", err)
		}
		log.Println("Server gracefully stopped")
	}()

	log.Println("Starting server on", cfg.Port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}

	return nil
}
