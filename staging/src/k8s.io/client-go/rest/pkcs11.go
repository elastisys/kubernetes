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

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var errNotImplemented = errors.New("not implemented")

// GetCertForPkcs11Info returns a certificate managed by a Hardware Security Module (HSM).
func GetCertForPkcs11Info(info *clientcmdapi.Pkcs11Info) (*tls.Certificate, error) {
	return nil, errNotImplemented
}
