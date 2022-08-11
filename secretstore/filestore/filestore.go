package filestore

import (
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/begmaroman/acme-dns-route53/secretstore"
)

type fileStore struct {
	configDir string
	log       *logrus.Logger
}

func New(configDir string, log *logrus.Logger) (secretstore.SecretStore, error) {
	if len(configDir) > 0 {
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			if err := os.MkdirAll(configDir, 0666); err != nil {
				return nil, errors.Wrap(err, "file-store: unable to create config directory")
			}
		}
	}

	return &fileStore{configDir: configDir, log: log}, nil
}

func (f *fileStore) Store(key, value string) error {
	filePath := f.configDir + "/" + key + ".pem"

	certOut, err := os.Create(filePath)
	if err != nil {
		return errors.Wrapf(err, "file-store: unable to create file with path '%s'", filePath)
	}
	defer certOut.Close()

	_, err = certOut.WriteString(value)
	if err != nil {
		return errors.Wrapf(err, "file-store: unable to write priv key to '%s'", filePath)
	}

	f.log.Infof("[%s] file-store: private key written to '%s'", key, filePath)

	return nil
}
