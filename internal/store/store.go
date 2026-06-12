package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	seccrypto "secretmgr/internal/crypto"
	"secretmgr/internal/model"
)

type Store struct {
	path string
}

func New() (*Store, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "secretmgr", "vault.json")
	return &Store{path: path}, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

func (s *Store) Initialize(password string) (*seccrypto.Session, *model.Vault, error) {
	env, sess, err := seccrypto.CreateNewVault(password)
	if err != nil {
		return nil, nil, err
	}
	if err := s.writeEnvelope(env); err != nil {
		return nil, nil, err
	}
	return sess, model.NewVault(), nil
}

func (s *Store) Unlock(password string) (*seccrypto.Session, *model.Vault, error) {
    env, err := s.readEnvelope()
    if err != nil {
        return nil, nil, err
    }

    vault, sess, err := seccrypto.UnlockVault(password, env)
    return sess, vault, err
}

func (s *Store) Save(vault *model.Vault, sess *seccrypto.Session) error {
	env, err := seccrypto.SaveVault(vault, sess)
	if err != nil {
		return err
	}
	return s.writeEnvelope(env)
}

func (s *Store) Logout() error {
	return nil
}

func (s *Store) readEnvelope() (*seccrypto.VaultEnvelope, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	return seccrypto.ParseEnvelope(data)
}

func (s *Store) writeEnvelope(env *seccrypto.VaultEnvelope) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var ErrNotFound = errors.New("vault not found")
