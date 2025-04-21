package repository

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/glebarez/sqlite" // SQLite driver
	"github.com/google/uuid"
)

type KeyRepository interface {
	GetCurrentKey() (string, error)
	RotateKey() (string, error)
}

type SQLiteKeyRepository struct {
	db         *sql.DB
	dbFilePath string
}

func NewSQLiteKeyRepository(dbFilePath string) (KeyRepository, error) {
	db, err := openOrCreateSQLiteDB(dbFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create key repository: %w", err)
	}

	return &SQLiteKeyRepository{db: db, dbFilePath: dbFilePath}, nil
}

func openOrCreateSQLiteDB(dbFilePath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbFilePath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)

	if err != nil {
		return nil, err
	}

	// If no active key exists, create one
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys WHERE is_active = 1").Scan(&count)
	if err != nil {
		return nil, err
	}

	if count == 0 {
		newKey := uuid.New().String()
		_, err = db.Exec("INSERT INTO keys (key, is_active) VALUES (?, 1)", newKey)
		if err != nil {
			return nil, err
		}
		log.Println("Generated initial signing key.")
	}

	return db, nil
}

func (r *SQLiteKeyRepository) GetCurrentKey() (string, error) {
	var key string
	err := r.db.QueryRow("SELECT key FROM keys WHERE is_active = 1").Scan(&key)
	if err != nil {
		return "", err
	}
	return key, nil
}

func (r *SQLiteKeyRepository) RotateKey() (string, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return "", err
	}

	// Deactivate the current key
	_, err = tx.Exec("UPDATE keys SET is_active = 0 WHERE is_active = 1")
	if err != nil {
		tx.Rollback()
		return "", err
	}

	// Generate a new key
	newKey := uuid.New().String()
	_, err = tx.Exec("INSERT INTO keys (key, is_active) VALUES (?, 1)", newKey)
	if err != nil {
		tx.Rollback()
		return "", err
	}

	err = tx.Commit()
	if err != nil {
		return "", err
	}

	log.Println("Rotated signing key.")
	return newKey, nil
}
