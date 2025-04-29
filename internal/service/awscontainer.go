// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//go:build awscontainer

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/google/uuid"

	"github.com/drakkan/sftpgo/v2/internal/config"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpd"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	installCodeName = "SFTPGo_Installation_Code"
)

var (
	awsProductCode = ""
)

func registerAWSContainer(disableAWSInstallationCode bool) error {
	if awsProductCode == "" {
		return errors.New("product code not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := getAWSConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to get config to register AWS container: %w", err)
	}
	if !disableAWSInstallationCode {
		if err := setInstallationCode(cfg); err != nil {
			return err
		}
	}
	requestNonce, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("unable to generate nonce for metering API: %w", err)
	}
	svc := marketplacemetering.NewFromConfig(cfg)
	result, err := svc.RegisterUsage(ctx, &marketplacemetering.RegisterUsageInput{
		ProductCode:      aws.String(awsProductCode),
		PublicKeyVersion: aws.Int32(1),
		Nonce:            aws.String(requestNonce.String()),
	})
	if err != nil {
		return fmt.Errorf("unable to register API operation for AWSMarketplace Metering: %w", err)
	}
	logger.Debug(logSender, "", "API operation for AWSMarketplace Metering registered, token %q",
		util.GetStringFromPointer(result.Signature))
	return nil
}

func getAWSConfig(ctx context.Context) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return cfg, fmt.Errorf("unable to get config to register AWS container: %w", err)
	}
	if cfg.Region == "" {
		svc := imds.NewFromConfig(cfg)
		region, err := svc.GetRegion(ctx, &imds.GetRegionInput{})
		if err == nil {
			logger.Debug(logSender, "", "AWS region from imds %q", region.Region)
			cfg.Region = region.Region
		} else {
			logger.Warn(logSender, "", "unable to get region from imds, continuing anyway, error: %v", err)
		}
	}
	return cfg, nil
}

func setInstallationCode(cfg aws.Config) error {
	if dataprovider.HasAdmin() {
		return nil
	}
	installationCode := util.GenerateUniqueID()
	requestToken, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("unable to generate client request token: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := secretsmanager.NewFromConfig(cfg)
	_, err = svc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(installCodeName),
	})
	if err == nil {
		// update existing secret
		result, err := svc.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:           aws.String(installCodeName),
			ClientRequestToken: aws.String(requestToken.String()),
			SecretString:       aws.String(installationCode),
		})
		if err != nil {
			return fmt.Errorf("unable to update installation code: %w", err)
		}
		logger.Debug(logSender, "", "installation code updated, secret name %q, arn %q, version id %q",
			util.GetStringFromPointer(result.Name), util.GetStringFromPointer(result.ARN),
			util.GetStringFromPointer(result.VersionId))
	} else {
		// create new secret
		logger.Debug(logSender, "", "unable to get the current installation secret, trying to create a new one, error: %v", err)
		result, err := svc.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:               aws.String(installCodeName),
			ClientRequestToken: aws.String(requestToken.String()),
			SecretString:       aws.String(installationCode),
		})
		if err != nil {
			return fmt.Errorf("unable to create installation code: %w", err)
		}
		logger.Debug(logSender, "", "installation code set, secret name %q, arn %q, version id %q",
			util.GetStringFromPointer(result.Name), util.GetStringFromPointer(result.ARN),
			util.GetStringFromPointer(result.VersionId))
	}
	httpdConfig := config.GetHTTPDConfig()
	httpdConfig.Setup.InstallationCode = installationCode
	httpdConfig.Setup.InstallationCodeHint = "Installation code stored in Secrets Manager"
	config.SetHTTPDConfig(httpdConfig)
	httpd.SetInstallationCodeResolver(resolveInstallationCode)

	return nil
}

// function called to validate the user provided secret
func resolveInstallationCode(defaultInstallationCode string) string {
	logger.Debug(logSender, "", "resolving installation code")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := getAWSConfig(ctx)
	if err != nil {
		logger.Error(logSender, "", "unable to get config to resolve installation code: %v", err)
		return defaultInstallationCode
	}

	svc := secretsmanager.NewFromConfig(cfg)
	result, err := svc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(installCodeName),
	})
	if err != nil {
		logger.Error(logSender, "", "unable to resolve installation code: %v", err)
		return defaultInstallationCode
	}

	resolvedCode := util.GetStringFromPointer(result.SecretString)
	if resolvedCode == "" {
		logger.Error(logSender, "", "resolved installation code is empty")
		return defaultInstallationCode
	}
	logger.Debug(logSender, "", "installation code resolved")
	return resolvedCode
}
