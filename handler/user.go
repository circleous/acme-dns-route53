package handler

import (
	"crypto"
	"encoding/pem"
	"strings"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/registration"
	"github.com/pkg/errors"
)

// CertUser is the simple implementation of acme.User interface
type CertUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

// NewCertUser is the constructor of CertUser
func NewCertUser(email string) *CertUser {
	return &CertUser{
		Email: email,
	}
}

// GetEmail returns email of the user
func (u *CertUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns registration.Resource model of the user
func (u CertUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the private key of the user
func (u *CertUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u *CertUser) GetEncodedPrivateKey() (string, error) {
	var certOut strings.Builder

	pemKey := certcrypto.PEMBlock(u.key)
	if err := pem.Encode(&certOut, pemKey); err != nil {
		return "", errors.Wrap(err, "unable to encode private key")
	}

	return certOut.String(), nil
}
