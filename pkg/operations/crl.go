package operations

import (
	"context"
	"fmt"
	"io"
	"reflect"

	"github.com/3scale/aws-cvpn-pki-manager/pkg/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
)

// GetCRLRequest is the structure containing
// the required data to issue a new certificate
type GetCRLRequest struct {
	Client       *api.Client
	VaultPKIPath string
}

// GetCRL return the Client Revocation List PEM as a []byte
func GetCRL(r *GetCRLRequest, logger logr.Logger) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.VaultApiTimeout)
	defer cancel()
	rsp, err := r.Client.Logical().ReadRawWithContext(ctx, fmt.Sprintf("/%s/crl/pem", r.VaultPKIPath))
	if err != nil {
		logger.Error(err, fmt.Sprintf("unable to retrieve CRL from Vault at path /%s/crl/pem", r.VaultPKIPath))
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		logger.Error(err, fmt.Sprintf("unable to read response body in call to /v1/%s/crl/pem", r.VaultPKIPath))
	}

	return data, nil
}

// UpdateCRLRequest is the structure containing
// the required data to issue a new certificate
type UpdateCRLRequest struct {
	Client              *api.Client
	VaultPKIPath        string
	ClientVPNEndpointID string
}

// UpdateCRL maintains the CRL to keep just one active certificte per
// VPN user. This will always be the one emitted at a later date. Users
// can also have all their certificates revoked.
func UpdateCRL(r *UpdateCRLRequest, logger logr.Logger) ([]byte, error) {

	// Get the list of users
	users, err := ListUsers(
		&ListUsersRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		}, logger)
	if err != nil {
		return nil, err
	}

	//For each user, get the list of certificates, and revoke all of them but the latest
	for _, crts := range users {
		err := revokeUserCertificates(r.Client, r.VaultPKIPath, crts, false, logger)
		if err != nil {
			return nil, err
		}
	}

	// Get the updated CRL
	crl, err := GetCRL(
		&GetCRLRequest{
			Client:       r.Client,
			VaultPKIPath: r.VaultPKIPath,
		}, logger)
	if err != nil {
		return nil, err
	}

	// Upload new CRL to AWS Client VPN endpoint
	ctx1, cancel1 := context.WithTimeout(context.Background(), config.AwsApiTimeout)
	defer cancel1()
	cfg, err := awsconfig.LoadDefaultConfig(ctx1)
	if err != nil {
		logger.Error(err, "unable to load AWS EC2 client")
		return nil, err
	}
	svc := ec2.NewFromConfig(cfg)
	cvpnCRL, err := svc.ExportClientVpnClientCertificateRevocationList(ctx1,
		&ec2.ExportClientVpnClientCertificateRevocationListInput{
			ClientVpnEndpointId: &r.ClientVPNEndpointID,
		})
	if err != nil {
		logger.Error(err, "error in AWS call exportClientVpnClientCertificateRevocationList")
		return nil, err
	}

	//reset the timeout
	ctx2, cancel2 := context.WithTimeout(context.Background(), config.AwsApiTimeout)
	defer cancel2()

	// Handle the case that no CRL has been uploaded yet. The API
	// will return a struct without the 'CertificateRevocationList'
	// property causing an invalid memory address error if not
	// checked beforehand.
	if reflect.ValueOf(*cvpnCRL).FieldByName("CertificateRevocationList").Elem().IsValid() {
		if *cvpnCRL.CertificateRevocationList != string(crl) {
			// CRL needs update
			_, err = svc.ImportClientVpnClientCertificateRevocationList(ctx2,
				&ec2.ImportClientVpnClientCertificateRevocationListInput{
					CertificateRevocationList: aws.String(string(crl)),
					ClientVpnEndpointId:       aws.String(r.ClientVPNEndpointID),
				})
			if err != nil {
				logger.Error(err, "error in AWS call importClientVpnClientCertificateRevocationListInput")
				return nil, err
			}
			logger.Info("Updated CRL in AWS Client VPN endpoint")
		} else {
			logger.Info("CRL does not need to be updated")
		}
	} else {
		// CRL first time import
		_, err = svc.ImportClientVpnClientCertificateRevocationList(ctx2,
			&ec2.ImportClientVpnClientCertificateRevocationListInput{
				CertificateRevocationList: aws.String(string(crl)),
				ClientVpnEndpointId:       aws.String(r.ClientVPNEndpointID),
			})
		if err != nil {
			logger.Error(err, "error in AWS call importClientVpnClientCertificateRevocationListInput")
			return nil, err
		}
		logger.Info("First upload of the CRL to the Client VPN endpoint")
	}

	return crl, nil
}

// RotateCRLRequest is the structure containing the
// required data to rotate the Client Revocation List
type RotateCRLRequest struct {
	Client              *api.Client
	VaultPKIPath        string
	ClientVPNEndpointID string
}

func RotateCRL(r *RotateCRLRequest, logger logr.Logger) ([]byte, error) {

	ctx, cancel := context.WithTimeout(context.Background(), config.VaultApiTimeout)
	defer cancel()
	_, err := r.Client.Logical().ReadRawWithContext(ctx, fmt.Sprintf("/%s/crl/rotate", r.VaultPKIPath))
	if err != nil {
		logger.Error(err, fmt.Sprintf("error in Vault call to /%s/crl/rotate", r.VaultPKIPath))
		return nil, err
	}

	crl, err := UpdateCRL(
		&UpdateCRLRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		}, logger)
	if err != nil {
		return nil, err
	}

	return crl, nil
}
