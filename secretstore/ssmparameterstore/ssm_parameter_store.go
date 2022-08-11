package ssmparameterstore

import (
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/begmaroman/acme-dns-route53/secretstore"
)

type ssmParameterStore struct {
	ssm *ssm.SSM
	log *logrus.Logger

	configDir string
}

var secureStringType string = "SecureString"

func New(provider client.ConfigProvider, configDir string, log *logrus.Logger) secretstore.SecretStore {
	return &ssmParameterStore{
		ssm: ssm.New(provider),
		log: log,

		configDir: configDir,
	}
}

func (s *ssmParameterStore) Store(key, value string) error {
	parameterName := s.configDir + "/" + key

	payload := &ssm.PutParameterInput{
		Name:  &parameterName,
		Value: &value,
		Type:  &secureStringType,
	}

	_, err := s.ssm.PutParameter(payload)
	if err != nil {
		return errors.Wrap(err, "ssm-parameter-store: unable to put secret value")
	}

	s.log.Infof("[%s] ssm-parameter-store: private key written to '%s'", key, parameterName)

	return nil
}
