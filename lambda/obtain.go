package lambda

import (
	"errors"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/begmaroman/acme-dns-route53/certstore/acmstore"
	"github.com/begmaroman/acme-dns-route53/handler"
	"github.com/begmaroman/acme-dns-route53/handler/r53dns"
	"github.com/begmaroman/acme-dns-route53/notifier/awsns"
	"github.com/begmaroman/acme-dns-route53/secretstore"
	"github.com/begmaroman/acme-dns-route53/secretstore/filestore"
	"github.com/begmaroman/acme-dns-route53/secretstore/secretmanagerstore"
	"github.com/begmaroman/acme-dns-route53/secretstore/ssmparameterstore"
)

const (
	// ConfigDir is the default configuration directory
	ConfigDir = "/tmp"
)

var (
	// ErrEmailMissing is the error when email is not provided
	ErrEmailMissing = errors.New("email must be filled")

	// ErrDomainsMissing is the error when the domains list is empty
	ErrDomainsMissing = errors.New("domains list must not be filled")
)

// Payload contains payload data
type Payload struct {
	Domains     []string `json:"domains"`
	Email       string   `json:"email"`
	Staging     string   `json:"staging"`
	Topic       string   `json:"topic"`
	RenewBefore int      `json:"renew_before"`

	SecretStoreType   string `json:"secret_store_type"`
	SecretStorePrefix string `json:"secret_store_prefix"`
}

func HandleLambdaEvent(payload Payload) error {
	var err error

	conf := InitConfig(payload)

	// Domains list must not be empty
	if len(conf.Domains) == 0 {
		return ErrDomainsMissing
	}

	// Email must be filled
	if len(conf.Email) == 0 {
		return ErrEmailMissing
	}

	log := logrus.New()

	var secretStore secretstore.SecretStore
	if conf.SecretStoreType == "ssm-parameter" {
		secretStore = ssmparameterstore.New(AWSSession, conf.SecretStorePrefix, log)
	} else if conf.SecretStoreType == "secret-manager" {
		secretStore = secretmanagerstore.New()
	} else {
		// Fallback using file store, force using tmp since we are in lambda env
		secretStore, err = filestore.New("/tmp", log)
		if err != nil {
			logrus.Errorf("unable to init file-store: %s\n", err)
			return err
		}
	}

	// Create a new handler
	certificateHandler := handler.NewCertificateHandler(&handler.CertificateHandlerOptions{
		Staging:           conf.Staging,
		NotificationTopic: conf.Topic,
		RenewBefore:       conf.RenewBefore * 24,
		Log:               log,
		Notifier:          awsns.New(AWSSession, log),    // Initialize SNS API client
		DNS01:             r53dns.New(AWSSession, log),   // Initialize DNS-01 challenge provider by Route 53
		Store:             acmstore.New(AWSSession, log), // Initialize ACM client
		SecretStore:       secretStore,
	})

	var wg sync.WaitGroup
	for _, domain := range conf.Domains {
		wg.Add(1)
		go func(domainCopy string) {
			defer wg.Done()

			if err := certificateHandler.Obtain(domainCopy, conf.Email); err != nil {
				logrus.Errorf("[%s] unable to obtain certificate: %s\n", domainCopy, err)
			}
		}(domain)
	}
	wg.Wait()

	return nil
}
