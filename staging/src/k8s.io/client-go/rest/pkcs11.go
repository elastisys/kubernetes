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

	"github.com/ThalesIgnite/crypto11"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var errNotImplemented = errors.New("not implemented")
var errPrivateKeyNotFound = errors.New("private key not found")
var errCertificateNotFound = errors.New("certificate not found")

func wrapError(err error) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) { return nil, err }
}

func wrapCertificate(cert *tls.Certificate) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) { return cert, nil }
}

var ctx *crypto11.Context

// GetCertForPkcs11Info returns a function returning a certificate managed by a Hardware Security Module (HSM).
func GetCertForPkcs11Info(info *clientcmdapi.Pkcs11Info) func() (*tls.Certificate, error) {
	var err error

	if ctx == nil {
		config := &crypto11.Config{
			Path:       info.Path,
			Pin:        info.Pin,
			SlotNumber: &info.SlotID,
		}

		ctx, err = crypto11.Configure(config)
		if err != nil {
			return wrapError(err)
		}
		// TODO: Don't keep context forever.
	}

	objectID := []byte{info.ObjectID}
	cert, err := ctx.FindCertificate(objectID, nil, nil)
	if err != nil {
		return wrapError(err)
	}
	if cert == nil {
		return wrapError(errCertificateNotFound)
	}

	key, err := ctx.FindKeyPair(objectID, nil)
	if err != nil {
		return wrapError(err)
	}
	if key == nil {
		return wrapError(errPrivateKeyNotFound)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}

	return wrapCertificate(tlsCert)
}
