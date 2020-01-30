/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rest

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/ThalesIgnite/crypto11"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var errNotImplemented = errors.New("not implemented")
var errPrivateKeyNotFound = errors.New("private key not found")
var errCertificateNotFound = errors.New("certificate not found")

func wrapError(err error) (func() (*tls.Certificate, error)) {
	return func() (*tls.Certificate, error) { return nil, err }
}

func wrapCertificate(cert *tls.Certificate) (func() (*tls.Certificate, error)) {
	return func() (*tls.Certificate, error) { return cert, nil }
}

var ctx *crypto11.Context

// GetCertForPkcs11Info returns a function returning a certificate managed by a Hardware Security Module (HSM).
func GetCertForPkcs11Info(info *clientcmdapi.Pkcs11Info) (func() (*tls.Certificate, error)) {
	var err error
	
	if ctx == nil {
		slotNumber := 0
		config := &crypto11.Config{
			Path: info.Path,
			Pin: info.Pin,
			SlotNumber: &slotNumber,
			MaxSessions: 2,
		}
	
		ctx, err = crypto11.Configure(config)
		if err != nil {
			return wrapError(err)
		}
		fmt.Println("Context configured successfully!")
		//defer ctx.Close()	
	}

	cert, err := ctx.FindCertificate([]byte{2}, nil, nil)
	if err != nil {
		fmt.Println(err)
		return wrapError(err)
	}
	if cert == nil {
		return wrapError(errCertificateNotFound)
	}
	fmt.Println("Certificate found!")
	fmt.Println(cert)

	key, err := ctx.FindKeyPair([]byte{2}, nil)
	if err != nil {
		return wrapError(err)
	}
	if key == nil {
		return wrapError(errPrivateKeyNotFound)
	}
	fmt.Println("Key found!")
	fmt.Println(key)

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{ cert.Raw },
		PrivateKey: key,
		Leaf: cert,
	}

	return wrapCertificate(tlsCert)
}
