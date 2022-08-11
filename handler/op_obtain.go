package handler

import (
	"fmt"
	"time"

	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/pkg/errors"
)

var (
	// registerOptions is the predefined registration.RegisterOptions struct with the default params
	registerOptions = registration.RegisterOptions{TermsOfServiceAgreed: true}
)

// Obtain creates a new SSL certificate or renews existing one for the given domains with the given email
func (h *CertificateHandler) Obtain(domain string, email string) error {

	// Check if there is existing an certificate for the given domains
	existingCert, err := h.store.Load(domain)
	if err != nil {
		return errors.Wrap(err, "handler: unable to load existing certificate")
	}

	if existingCert != nil {
		if sub := existingCert.NotAfter.Sub(time.Now()).Hours(); int(sub) > h.renewBefore {
			h.log.Infof("[%s] handler: left %d days to certificate will be expired", domain, time.Duration(sub/24))
			return nil
		}
	}

	// Load user
	certUser, err := getUser(h.toUserParams(email))
	if err != nil {
		return errors.Wrap(err, "handler: unable to load user")
	}

	// Create config
	config, err := getConfig(h.toConfigParams(certUser))
	if err != nil {
		return errors.Wrap(err, "handler: unable to create config")
	}

	// Create a client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "handler: unable to create lego client")
	}

	// Use DNS-01 challenge to verify that the given domain belongs to the current server
	if err = client.Challenge.SetDNS01Provider(h.dns01); err != nil {
		return errors.Wrap(err, "handler: failed to set DNS-01 provider")
	}

	// New users will need to register
	if certUser.Registration, err = client.Registration.Register(registerOptions); err != nil {
		return errors.Wrap(err, "handler: could not register Let's Encrypt account")
	}

	// Create a new request to obtain certificate
	crt, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    []string{domain},
		PrivateKey: nil,
		Bundle:     false,
		MustStaple: false,
	})
	if err != nil {
		return errors.Wrap(err, "handler: unable to obtain certificate")
	}

	// Store the obtained certificate
	if err := h.store.Store(crt, domain); err != nil {
		return errors.Wrap(err, "handler: unable to store certificates")
	}

	// Notify that the certificate has been obtained for the given domains
	if len(h.notificationTopic) > 0 {
		if err := h.notifier.Notify(h.notificationTopic, h.buildPublishMessage(domain)); err != nil {
			return errors.Wrap(err, "handler: failed to publish notification")
		}
	}

	// Store user's private key into config file by the config path
	var encodedPrivKey string
	if encodedPrivKey, err = certUser.GetEncodedPrivateKey(); err != nil {
		return errors.Wrap(err, "handler: unable to encode user's private key")
	}

	if err := h.secret.Store(domain, encodedPrivKey); err != nil {
		return errors.Wrap(err, "handler: unable to store user's private key")
	}

	h.log.Infof("[%s] handler: certificate successfully obtained and stored", domain)

	return nil
}

// buildPublishMessage builsd a message to publish by the given params
func (h *CertificateHandler) buildPublishMessage(domains string) string {
	return fmt.Sprintf("Certificates for the following domains successfully obtained: %s", domains)
}
