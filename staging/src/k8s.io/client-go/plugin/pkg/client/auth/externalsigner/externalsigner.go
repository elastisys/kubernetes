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

package externalsigner

import (
	// "bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	// "io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sync"

	// "crypto/rsa"
	// "go/types"

	// "runtime/debug"

	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog"
)

const (
	cfgPathExec = "pathExec"
)

func init() {
	if err := restclient.RegisterAuthProviderPlugin("externalSigner", newExternalSignerAuthProvider); err != nil {
		klog.Fatalf("Failed to register externalSigner auth plugin: %v", err)
	}
}

var cache = newClientCache()

type clientCache struct {
	mu sync.RWMutex

	cache map[cacheKey]*Authenticator
}

func newClientCache() *clientCache {
	return &clientCache{cache: make(map[cacheKey]*Authenticator)}
}

type cacheKey struct {
	json string
}

func (c *clientCache) getClient(cfg map[string]string) (*Authenticator, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfgJSON, _ := json.Marshal(cfg)
	client, ok := c.cache[cacheKey{json: string(cfgJSON)}]
	return client, ok
}

// setClient attempts to put the client in the cache but may return any clients
// with the same keys set before. This is so there's only ever one client for a provider.
// func (c *clientCache) setClient(path, slotID, objectID string, client *Authenticator) *Authenticator {
func (c *clientCache) setClient(cfg map[string]string, client *Authenticator) *Authenticator {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfgJSON, _ := json.Marshal(cfg)
	key := cacheKey{json: string(cfgJSON)}

	// If another client has already initialized a client for the given provider we want
	// to use that client instead of the one we're trying to set. This is so all transports
	// share a client and can coordinate around the same mutex when refreshing and writing
	// to the kubeconfig.
	if oldClient, ok := c.cache[key]; ok {
		return oldClient
	}

	c.cache[key] = client
	return client
}

type externalSigner struct {
	publicKey crypto.PublicKey
	cfg       map[string]string
}

func (priv *externalSigner) Public() crypto.PublicKey {
	fmt.Printf("[PUBLIC]\n")
	return priv.publicKey
}

func (priv *externalSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("[SIGN]\n")
	// fmt.Printf("digest: %s\n", b64.StdEncoding.EncodeToString(digest))
	// fmt.Printf("options: %d\n", opts.HashFunc())

	type ConfigMessage struct {
		APIVersion     string            `json:"apiVersion"`
		Kind           string            `json:"kind"`
		Digest         string            `json:"digest"`
		Configuration  map[string]string `json:"configuration"`
		SignerOptsType string            `json:"signerOptsType"`
		SignerOpts     string            `json:"signerOpts"`
		// SignerOpts     map[string]string `json:"signerOpts"`
	}

	// fmt.Printf("TypeOf(crypto.SignerOpts): %s\n", reflect.TypeOf(opts))

	signerOptsString, _ := json.Marshal(opts)

	config := ConfigMessage{
		APIVersion:    "external-signer.authentication.k8s.io/v1alpha1",
		Kind:          "Sign",
		Digest:        b64.StdEncoding.EncodeToString(digest),
		Configuration: priv.cfg,
		// SignerOptsType: "rsa.PSSOptions",
		SignerOptsType: reflect.TypeOf(opts).String(),
		SignerOpts:     string(signerOptsString),
	}

	b, _ := json.Marshal(config)

	fmt.Printf("Sing request : %s\n", string(b))

	cmd := exec.Command(priv.cfg[cfgPathExec], string(b))
	// cmd := exec.Command(priv.cfg[cfgPathExec])
	// buffer := bytes.Buffer{}
	// buffer.Write(b)
	// buffer.Write(b)
	// buffer.WriteString("\n")
	// cmd.Stdin = &buffer
	// cmd.Stdin = bytes.NewBuffer(b)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()

	// grepIn, _ := cmd.StdinPipe()
	// grepOut, _ := cmd.StdoutPipe()
	// cmd.Start()
	// grepIn.Write(b)
	// // grepIn.Close()
	// out, err := ioutil.ReadAll(grepOut)
	// cmd.Wait()

	if err != nil {
		return nil, fmt.Errorf("exec: %v", err)
	}
	fmt.Printf("Sign response: %s\n", string(out))

	type Message struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Signature  string `json:"signature"`
	}

	var record Message

	err = json.Unmarshal([]byte(out), &record)
	if err != nil {
		return nil, fmt.Errorf("exec: %v", err)
	}
	signature, err = b64.StdEncoding.DecodeString(record.Signature)
	return
}

func newExternalSignerAuthProvider(clusterAddress string, cfg map[string]string, persister restclient.AuthProviderConfigPersister) (restclient.AuthProvider, error) {
	// func newExternalSignerAuthProvider(clusterAddress string, cfg map[string]string, persister restclient.AuthProviderConfigPersister) (Authenticator, error) {
	fmt.Printf("[NEW AUTH PROVIDER]\n")
	// debug.PrintStack()

	type ConfigMessage struct {
		APIVersion    string            `json:"apiVersion"`
		Kind          string            `json:"kind"`
		Configuration map[string]string `json:"configuration"`
	}

	path := cfg[cfgPathExec]
	if path == "" {
		return nil, fmt.Errorf("Must provide %s", cfgPathExec)
	}

	// pinString := cfg[cfgPIN]
	// fmt.Printf("pinString: %s\n", pinString)

	if provider, ok := cache.getClient(cfg); ok {
		return provider, nil
	}

	config := ConfigMessage{
		APIVersion:    "external-signer.authentication.k8s.io/v1alpha1",
		Kind:          "Certificate",
		Configuration: cfg,
	}

	b, _ := json.Marshal(config)
	fmt.Printf("Crertificate request: %s\n", string(b))

	cmd := exec.Command(cfg[cfgPathExec], string(b))
	// cmd := exec.Command(cfg[cfgPathExec])
	// buffer := bytes.Buffer{}
	// buffer.Write(b)
	// buffer.WriteString("\n")
	// cmd.Stdin = &buffer

	// cmd.Stdin = bytes.NewBuffer(b)

	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()

	// grepIn, _ := cmd.StdinPipe()
	// grepOut, _ := cmd.StdoutPipe()
	// cmd.Start()
	// grepIn.Write(b)
	// grepIn.Close()
	// out, err := ioutil.ReadAll(grepOut)
	// cmd.Wait()

	// fmt.Printf("External certificate output: %s\n", out)
	if err != nil {
		return nil, fmt.Errorf("exec: %v", err)
	}
	fmt.Printf("Certificate response: %s\n", string(out))

	type Message struct {
		APIVersion  string `json:"apiVersion"`
		Kind        string `json:"kind"`
		Certificate string `json:"certificate"`
		// PublicKey   string `json:"publicKey"`
	}

	var record Message

	err = json.Unmarshal([]byte(out), &record)
	if err != nil {
		return nil, fmt.Errorf("exec: %v", err)
	}

	certExt, err := b64.StdEncoding.DecodeString(record.Certificate)

	cert, certErr := x509.ParseCertificate([]byte(certExt))
	if certErr != nil {
		fmt.Printf("Error: %s\n", certErr)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certExt},
		PrivateKey:  &externalSigner{cert.PublicKey, cfg},
		// PrivateKey: &externalSigner{cert.PublicKey, cfg, protocol},
	}

	provider := &Authenticator{
		tlsCert: tlsCert,
	}

	// return cache.setClient(path, slotIDString, objectIDString, provider), nil
	return cache.setClient(cfg, provider), nil
}

type Authenticator struct {
	tlsCert *tls.Certificate
}

func (p *Authenticator) Login() error {
	return fmt.Errorf("not yet implemented")
}

func (p *Authenticator) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	// rtJSON, err := json.Marshal(rt)
	// if err != nil {
	// 	fmt.Printf("[WrapTransport] Error: %s\n", err)
	// }
	// fmt.Printf("[WrapTransport] rtJSON: %s\n", string(rtJSON))
	return rt
}

func (p *Authenticator) UpdateTransportConfig(conf *transport.Config) error {
	conf.TLS.GetCert = func() (*tls.Certificate, error) { return p.tlsCert, nil }

	// confJSON, err := json.Marshal(conf)
	// if err != nil {
	// 	fmt.Printf("Error: %s\n", err)
	// }
	// fmt.Printf("[UpdateTransportConfig] confJSON: %s\n", string(confJSON))

	// tlsConfig, err := transport.TLSConfigFor(conf)
	// if err != nil {
	// 	fmt.Printf("Error: %s\n", err)
	// }
	// tlsConfigJSON, err := json.Marshal(tlsConfig)
	// if err != nil {
	// 	fmt.Printf("Error: %s\n", err)
	// }
	// fmt.Printf("[UpdateTransportConfig] tlsConfigJSON: %s\n", string(tlsConfigJSON))
	return nil
}
