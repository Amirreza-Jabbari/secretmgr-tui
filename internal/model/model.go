package model

import "time"

type Vault struct {
	Documents []Document `json:"documents"`
}

type Document struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Items     []Item    `json:"items"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Item struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewVault() *Vault {
	return &Vault{Documents: make([]Document, 0)}
}
