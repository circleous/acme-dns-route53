package cmd

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/begmaroman/acme-dns-route53/certstore/acmstore"
	"github.com/begmaroman/acme-dns-route53/cmd/flags"
	"github.com/begmaroman/acme-dns-route53/handler"
	"github.com/begmaroman/acme-dns-route53/handler/r53dns"
	"github.com/begmaroman/acme-dns-route53/notifier/awsns"
	"github.com/begmaroman/acme-dns-route53/secretstore"
	"github.com/begmaroman/acme-dns-route53/secretstore/filestore"
	"github.com/begmaroman/acme-dns-route53/secretstore/secretmanagerstore"
	"github.com/begmaroman/acme-dns-route53/secretstore/ssmparameterstore"
)

// certificateObtainCmd represents the certificate obtaining command
var certificateObtainCmd = &cobra.Command{
	Use:   "obtain",
	Short: "Obtain SSL certificates",
	Long:  `This command creates new SSL certificates or renews existing ones for the given domains using the given parameters.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		// Inits needed parameters
		domains := flags.GetDomainsFlagValue(cmd)
		email := flags.GetEmailFlagValue(cmd)

		// Init a common logger
		log := logrus.New()

		var secretStore secretstore.SecretStore
		secretStoreType := flags.GetSecretStoreTypeFlagValue(cmd)
		configDir := flags.GetConfigPathFlagValue(cmd)

		if secretStoreType == "ssm-parameter" {
			secretStore = ssmparameterstore.New(AWSSession, configDir, log)
		} else if secretStoreType == "secret-manager" {
			secretStore = secretmanagerstore.New()
		} else {
			// Fallback using file store, force using tmp since we are in lambda env
			secretStore, err = filestore.New(configDir, log)
			if err != nil {
				logrus.Errorf("unable to init file-store: %s\n", err)
				return err
			}
		}

		// Create a new certificates handler
		h := handler.NewCertificateHandler(&handler.CertificateHandlerOptions{
			SecretStoreType:   flags.GetSecretStoreTypeFlagValue(cmd),
			Staging:           flags.GetStagingFlagValue(cmd),
			NotificationTopic: flags.GetTopicFlagValue(cmd),
			RenewBefore:       flags.GetRenewBeforeFlagValue(cmd) * 24,
			Log:               log,
			Notifier:          awsns.New(AWSSession, log),    // Initialize SNS API client
			DNS01:             r53dns.New(AWSSession, log),   // Initialize DNS-01 challenge provider by Route 53
			Store:             acmstore.New(AWSSession, log), // Initialize ACM client
			SecretStore:       secretStore,
		})

		var wg sync.WaitGroup
		for _, domain := range domains {
			wg.Add(1)
			go func(domainCopy string) {
				defer wg.Done()

				if err := h.Obtain(domainCopy, email); err != nil {
					logrus.Errorf("[%s] unable to obtain certificate: %s\n", domainCopy, err)
				}
			}(domain)
		}
		wg.Wait()

		return nil
	},
}

func init() {
	flags.AddDomainsFlag(certificateObtainCmd)
	flags.AddEmailFlag(certificateObtainCmd)
	flags.AddSecretStoreTypeFlag(certificateObtainCmd)
	flags.AddConfigPathFlag(certificateObtainCmd)
	flags.AddStagingFlag(certificateObtainCmd)
	flags.AddTopicFlag(certificateObtainCmd)
	flags.AddRenewBeforeFlag(certificateObtainCmd)

	RootCmd.AddCommand(certificateObtainCmd)
}
