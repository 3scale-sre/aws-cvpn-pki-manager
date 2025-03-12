package operations

import "time"

// Certificate represents a certificate stored in the
// vault cvpn-pki secret engine
type Certificate struct {
	SerialNumber   string    `json:"serial"`
	IssuerCN       string    `json:"issuerCN"`
	SubjectCN      string    `json:"subjectCN"`
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
	Revoked        bool      `json:"revoked"`
	CertificatePEM string    `json:"certificate-pem"`
}
