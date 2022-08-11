package secretmanagerstore

import "errors"

type secretManagerStore struct{}

func New() *secretManagerStore {
	return &secretManagerStore{}
}

func (f *secretManagerStore) Store(key, value string) error {
	return errors.New("unimplemented")
}
