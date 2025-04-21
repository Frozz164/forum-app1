package repository

import (
	"context"
	"log"
	"time"

	"forum-app/auth-service/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *domain.RefreshToken) error
	Get(ctx context.Context, token string) (*domain.RefreshToken, error)
	Delete(ctx context.Context, token string) error
}

type MongoDBRefreshTokenRepository struct {
	client     *mongo.Client
	dbName     string
	collection string
}

func NewMongoDBRefreshTokenRepository(mongoURI, dbName string) (RefreshTokenRepository, error) {
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, err
	}

	// Check the connection
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	log.Println("Connected to MongoDB!")

	return &MongoDBRefreshTokenRepository{
		client:     client,
		dbName:     dbName,
		collection: "refresh_tokens",
	}, nil
}

func (r *MongoDBRefreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
	collection := r.client.Database(r.dbName).Collection(r.collection)

	_, err := collection.InsertOne(ctx, token)
	return err
}

func (r *MongoDBRefreshTokenRepository) Get(ctx context.Context, token string) (*domain.RefreshToken, error) {
	collection := r.client.Database(r.dbName).Collection(r.collection)

	var refreshToken domain.RefreshToken
	filter := bson.M{"token": token}
	err := collection.FindOne(ctx, filter).Decode(&refreshToken)
	if err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

func (r *MongoDBRefreshTokenRepository) Delete(ctx context.Context, token string) error {
	collection := r.client.Database(r.dbName).Collection(r.collection)

	filter := bson.M{"token": token}
	_, err := collection.DeleteOne(ctx, filter)
	return err
}

func (r *MongoDBRefreshTokenRepository) CloseMongoDBConnection() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := r.client.Disconnect(ctx); err != nil {
		panic(err)
	}
}
