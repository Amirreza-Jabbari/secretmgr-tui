package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"secretmgr/internal/model"
)

const (
	VaultVersion = 1
	saltSize     = 16
	keySize      = 32
)

type VaultEnvelope struct {
	Version      int    `json:"version"`
	PasswordHash string `json:"password_hash"`
	KDFSalt      string `json:"kdf_salt"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

type Session struct {
	PasswordHash string
	Salt         []byte
	Key          []byte
}

func CreateNewVault(password string) (*VaultEnvelope, *Session, error) {
	if len(password) < 8 {
		return nil, nil, errors.New("password must be at least 8 characters")
	}

	salt, err := randomBytes(saltSize)
	if err != nil {
		return nil, nil, err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	key := deriveKey(password, salt)
	vault := model.NewVault()
	envelope, err := encryptVault(vault, key, string(passwordHash), salt)
	if err != nil {
		return nil, nil, err
	}

	sess := &Session{
		PasswordHash: string(passwordHash),
		Salt:         salt,
		Key:          key,
	}

	return envelope, sess, nil
}

func UnlockVault(password string, env *VaultEnvelope) (*model.Vault, *Session, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(env.PasswordHash), []byte(password)); err != nil {
		return nil, nil, errors.New("invalid password")
	}

	salt, err := base64.StdEncoding.DecodeString(env.KDFSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid salt: %w", err)
	}

	key := deriveKey(password, salt)
	vault, err := decryptVault(env, key)
	if err != nil {
		return nil, nil, err
	}

	sess := &Session{
		PasswordHash: env.PasswordHash,
		Salt:         salt,
		Key:          key,
	}

	return vault, sess, nil
}

func SaveVault(vault *model.Vault, sess *Session) (*VaultEnvelope, error) {
	return encryptVault(vault, sess.Key, sess.PasswordHash, sess.Salt)
}

func EncryptVaultJSON(vault *model.Vault, sess *Session) ([]byte, error) {
	env, err := SaveVault(vault, sess)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(env, "", "  ")
}

func ParseEnvelope(data []byte) (*VaultEnvelope, error) {
	var env VaultEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	if env.Version != VaultVersion {
		return nil, fmt.Errorf("unsupported vault version %d", env.Version)
	}
	return &env, nil
}

func decryptVault(env *VaultEnvelope, key []byte) (*model.Vault, error) {
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("unable to decrypt vault; password may be wrong or vault file corrupted")
	}

	var vault model.Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}
	if vault.Documents == nil {
		vault.Documents = make([]model.Document, 0)
	}
	return &vault, nil
}

func encryptVault(vault *model.Vault, key []byte, passwordHash string, salt []byte) (*VaultEnvelope, error) {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &VaultEnvelope{
		Version:      VaultVersion,
		PasswordHash: passwordHash,
		KDFSalt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, keySize)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
