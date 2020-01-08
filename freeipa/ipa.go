package freeipa

import (
	"fmt"
	"io/ioutil"
	"log"

	ipa "github.com/gnvk/goipa"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

type IpaServer struct {
	Host     string
	Realm    string
	Username string
	Password string
}

func Sign(cr *cmapi.CertificateRequest, ipaServer *IpaServer) ([]byte, []byte, error) {
	client := ipa.NewClient(ipaServer.Host, ipaServer.Realm)
	err := client.RemoteLogin(ipaServer.Username, ipaServer.Password)
	if err != nil {
		log.Fatal(err)
	}

	principal := fmt.Sprintf("nifi/%s@%s", ipaServer.Host, ipaServer.Realm)
	profile := "caIPAserviceCert"
	cert, err := client.CertRequest(principal, string(cr.Spec.CSRPEM), profile)
	if err != nil {
		return nil, nil, err
	}
	certPem, err := cert.CertPem()
	log.Print(cert.CaCn)
	if err != nil {
		return nil, nil, err
	}
	certPemBytes := []byte(certPem)

	// TODO get from issuer
	caPemBytes, err := ioutil.ReadFile("/etc/ipa/ca.crt")
	if err != nil {
		return nil, nil, err
	}

	return certPemBytes, caPemBytes, nil
}
