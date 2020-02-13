/*
Copyright 2020 The Kubernetes Authors.

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

package pkcs11

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/ThalesIgnite/crypto11"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog"
)

const (
	cfgPath     = "path"
	cfgPIN      = "pin"
	cfgSlotID   = "slot-id"
	cfgObjectID = "object-id"
)

var (
	globalCache = newCache()
)

func newCache() *cache {
	return &cache{m: make(map[cacheKey]*crypto11.Context)}
}

type cacheKey struct {
	path   string
	slotID int
	// We don't put pin in cacheKey
}

type cache struct {
	mu sync.Mutex
	m  map[cacheKey]*crypto11.Context
}

func (c *cache) get(path string, pin string, slotID int) (*crypto11.Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey{path: path, slotID: slotID}
	ctx, ok := c.m[key]
	if ok {
		return ctx, nil
	}

	config := &crypto11.Config{
		Path:       path,
		Pin:        pin,
		SlotNumber: &slotID,
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, err
	}

	c.m[key] = ctx

	return ctx, nil
}

func init() {
	if err := restclient.RegisterAuthProviderPlugin("pkcs11", newPKCS11AuthProvider); err != nil {
		klog.Fatalf("Failed to register pkcs11 auth plugin: %v", err)
	}
}

func newPKCS11AuthProvider(clusterAddress string, cfg map[string]string, persister restclient.AuthProviderConfigPersister) (restclient.AuthProvider, error) {
	path := cfg[cfgPath]
	if path == "" {
		return nil, fmt.Errorf("Must provide %s", cfgPath)
	}

	pin := cfg[cfgPIN]
	var slotID int64
	var objectID int64
	var err error

	if slotID, err = strconv.ParseInt(cfg[cfgSlotID], 10, 32); err != nil {
		return nil, fmt.Errorf("Must provide integer %s: %v", cfgSlotID, err)
	}
	if objectID, err = strconv.ParseInt(cfg[cfgObjectID], 10, 32); err != nil {
		return nil, fmt.Errorf("Must provide integer %s: %v", cfgObjectID, err)
	}

	ctx, err := globalCache.get(path, pin, int(slotID))
	if err != nil {
		return nil, err
	}

	baObjectID := []byte{byte(objectID)}
	cert, err := ctx.FindCertificate(baObjectID, nil, nil)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("Certificate in slotID %v with objectID %v not found", slotID, objectID);
	}

	key, err := ctx.FindKeyPair(baObjectID, nil)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("Private key in slotID %v with objectID %v not found", slotID, objectID);
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}

	a := &Authenticator{
		tlsCert: tlsCert,
	}

	return a, nil
}

type Authenticator struct {
	tlsCert *tls.Certificate
}

func (p *Authenticator) Login() error {
	return fmt.Errorf("not yet implemented")
}

func (p *Authenticator) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return rt
}

func (p *Authenticator) UpdateTransportConfig(conf *transport.Config) error {
	conf.TLS.GetCert = func() (*tls.Certificate, error) { return p.tlsCert, nil }
	return nil
}
