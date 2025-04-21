package main

import (
	"log"

	"forum-app/auth-service/internal"
)

func main() {
	if err := internal.Run(); err != nil {
		log.Fatal(err)
	}
}
