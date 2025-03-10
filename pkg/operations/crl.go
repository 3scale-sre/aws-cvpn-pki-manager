package operations

import (
	"fmt"
	"io/ioutil"
	"log"
	"reflect"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/vault/api"
)

// GetCRLRequest is the structure containing
// the required data to issue a new certificate
type GetCRLRequest struct {
	Client       *api.Client
	VaultPKIPath string
}

// GetCRL return the Client Revocation List PEM as a []byte
func GetCRL(r *GetCRLRequest) ([]byte, error) {
	req := r.Client.NewRequest("GET", fmt.Sprintf("/v1/%s/crl/pem", r.VaultPKIPath))
	rsp, err := r.Client.RawRequest(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
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
func UpdateCRL(r *UpdateCRLRequest) ([]byte, error) {

	// Get the list of users
	users, err := ListUsers(
		&ListUsersRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		})
	if err != nil {
		return nil, err
	}

	//For each user, get the list of certificates, and revoke all of them but the latest
	for _, crts := range users {
		err := revokeUserCertificates(r.Client, r.VaultPKIPath, crts, false)
		if err != nil {
			return nil, err
		}
	}

	// Get the updated CRL
	crl, err := GetCRL(
		&GetCRLRequest{
			Client:       r.Client,
			VaultPKIPath: r.VaultPKIPath,
		})
	if err != nil {
		return nil, err
	}

	// Upload new CRL to AWS Client VPN endpoint
	svc := ec2.New(session.New())

	cvpnCRL, err := svc.ExportClientVpnClientCertificateRevocationList(
		&ec2.ExportClientVpnClientCertificateRevocationListInput{
			ClientVpnEndpointId: aws.String(r.ClientVPNEndpointID),
		})
	if err != nil {
		return nil, err
	}

	// Handle the case that no CRL has been uploaded yet. The API
	// will return a struct without the 'CertificateRevocationList'
	// property causing an invalid memory address error if not
	// checked beforehand.
	if reflect.ValueOf(*cvpnCRL).FieldByName("CertificateRevocationList").Elem().IsValid() {
		if *cvpnCRL.CertificateRevocationList != string(crl) {
			// CRL needs update
			_, err = svc.ImportClientVpnClientCertificateRevocationList(
				&ec2.ImportClientVpnClientCertificateRevocationListInput{
					CertificateRevocationList: aws.String(string(crl)),
					ClientVpnEndpointId:       aws.String(r.ClientVPNEndpointID),
				})
			if err != nil {
				return nil, err
			}
			log.Println("Updated CRL in AWS Client VPN endpoint")
		} else {
			log.Println("CRL does not need to be updated")
		}
	} else {
		// CRL first time import
		_, err = svc.ImportClientVpnClientCertificateRevocationList(
			&ec2.ImportClientVpnClientCertificateRevocationListInput{
				CertificateRevocationList: aws.String(string(crl)),
				ClientVpnEndpointId:       aws.String(r.ClientVPNEndpointID),
			})
		log.Println("First upload of CRL to the CPN endpoint")
		if err != nil {
			return nil, err
		}
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

func RotateCRL(r *RotateCRLRequest) error {

	req := r.Client.NewRequest("GET", fmt.Sprintf("/v1/%s/crl/rotate", r.VaultPKIPath))
	_, err := r.Client.RawRequest(req)
	if err != nil {
		return err
	}

	_, err = UpdateCRL(
		&UpdateCRLRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		})
	if err != nil {
		return err
	}

	return nil
}
