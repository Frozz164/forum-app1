package domain

import "time"

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    time.Time
	RtExpires    time.Time
}

type AccessDetails struct {
	AccessUuid string
	UserId     int
}

type RefreshToken struct {
	ID        string    `json:"id" bson:"_id"`
	UserID    int       `json:"user_id" bson:"user_id"`
	Token     string    `json:"token" bson:"token"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}
