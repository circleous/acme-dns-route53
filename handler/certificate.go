package handler

import (
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/registration"
	"github.com/sirupsen/logrus"

	"github.com/begmaroman/acme-dns-route53/certstore"
	"github.com/begmaroman/acme-dns-route53/notifier"
	"github.com/begmaroman/acme-dns-route53/secretstore"
)

// CertificateHandlerOptions is the options of certificate handler
type CertificateHandlerOptions struct {
	SecretStoreType string

	Staging           bool
	NotificationTopic string
	RenewBefore       int

	SecretStore secretstore.SecretStore
	Store       certstore.CertStore
	Notifier    notifier.Notifier
	DNS01       challenge.Provider

	Log *logrus.Logger
}

// CertificateHandler is the certificates handler
type CertificateHandler struct {
	secretStoreType string

	isStaging         bool
	notificationTopic string
	renewBefore       int

	secret   secretstore.SecretStore
	store    certstore.CertStore
	notifier notifier.Notifier
	dns01    challenge.Provider
	log      *logrus.Logger
}

// NewCertificateHandler is the constructor of CertificateHandler
func NewCertificateHandler(opts *CertificateHandlerOptions) *CertificateHandler {
	return &CertificateHandler{
		secretStoreType:   opts.SecretStoreType,
		isStaging:         opts.Staging,
		secret:            opts.SecretStore,
		store:             opts.Store,
		notificationTopic: opts.NotificationTopic,
		renewBefore:       opts.RenewBefore,
		notifier:          opts.Notifier,
		dns01:             opts.DNS01,
		log:               opts.Log,
	}
}

// toConfigParams creates a new configParams model
func (h *CertificateHandler) toConfigParams(user registration.User) *configParams {
	return &configParams{
		user:      user,
		isStaging: h.isStaging,
		keyType:   certcrypto.RSA2048, // TODO: Create a flag to define key type
	}
}

// toUserParams creates a new userParams model
func (h *CertificateHandler) toUserParams(email string) *userParams {
	return &userParams{
		email:   email,
		keyType: certcrypto.RSA2048, // TODO: Create a flag to define key type
	}
}
