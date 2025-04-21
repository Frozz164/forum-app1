package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type AuthClient struct {
	baseURL string
}

func NewAuthClient(baseURL string) *AuthClient {
	return &AuthClient{baseURL: baseURL}
}

func (c *AuthClient) ValidateToken(token string) (bool, error) {
	reqBody := map[string]string{"token": token}
	jsonBody, _ := json.Marshal(reqBody)

	resp, err := http.Post(
		c.baseURL+"/validate",
		"application/json",
		bytes.NewBuffer(jsonBody),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.Valid, nil
}
