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
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"net/http"
	"sync"

	"crypto/rsa"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	pb "k8s.io/client-go/plugin/pkg/client/auth/externalsigner/v1alpha1"

	"google.golang.org/grpc"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog"
)

const (
	cfgPathSocket = "pathSocket"
)

var cache = newClientCache()

func init() {
	if err := restclient.RegisterAuthProviderPlugin("externalSigner", newExternalSignerAuthProvider); err != nil {
		klog.Fatalf("Failed to register externalSigner auth plugin: %v", err)
	}
}

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
	publicKey   crypto.PublicKey
	cfg         map[string]string
	clusterName string
	socketPath  string
}

func (priv *externalSigner) Public() crypto.PublicKey {
	return priv.publicKey
}

func (priv *externalSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Printf("[SIGN]\n")

	fmt.Printf("priv.socketPath: %s\n", priv.socketPath)

	conn, err := grpc.Dial(
		priv.socketPath,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))
	if err != nil {
		log.Printf("did not connect: %v", err)
		return nil, err
	}
	defer conn.Close()
	c := pb.NewExternalSignerServiceClient(conn)

	pSSOptions := opts.(*rsa.PSSOptions)

	sctx, scancel := context.WithTimeout(context.Background(), time.Minute)
	defer scancel()
	stream, err := c.Sign(sctx, &pb.SignatureRequest{
		Version:       "v1alpha1",
		ClusterName:   priv.clusterName,
		Configuration: priv.cfg,
		Digest:        digest,
		SignerType:    pb.SignatureRequest_RSAPSS,
		SignerOptsRSAPSS: &pb.SignatureRequest_RSAPSSOptions{
			SaltLenght: int32(pSSOptions.SaltLength),
			Hash:       uint32(opts.HashFunc()),
		},
	})
	if err != nil {
		log.Printf("could not sign: %v", err)
		return nil, err
	}

	for {
		sr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("received error from external plugin: %v", err)
		}

		switch x := sr.Content.(type) {
		case *pb.SignatureResponse_Signature:
			signature = x.Signature
		case *pb.SignatureResponse_UserPrompt:
			fmt.Printf("%s\n", x.UserPrompt)
		case nil:
			// The field is not set.
		default:
			return nil, fmt.Errorf("Signature has unexpected type %T", x)
		}
	}

	return signature, err
}

func newExternalSignerAuthProvider(clusterAddress string, cfg map[string]string, persister restclient.AuthProviderConfigPersister) (restclient.AuthProvider, error) {
	fmt.Printf("[NEW AUTH PROVIDER]\n")

	if provider, ok := cache.getClient(cfg); ok {
		fmt.Printf("Use cached\n")
		return provider, nil
	}
	fmt.Printf("Create new\n")

	path := cfg[cfgPathSocket]
	if path == "" {
		return nil, fmt.Errorf("Must provide %s", cfgPathSocket)
	}

	conn, err := grpc.Dial(
		path,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewExternalSignerServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stream, err := c.GetCertificate(ctx, &pb.CertificateRequest{
		Version:       "v1alpha1",
		ClusterName:   clusterAddress,
		Configuration: cfg,
	})
	if err != nil {
		return nil, fmt.Errorf("could not get certificate: %v", err)
	}

	var certRaw []byte

	for {
		cr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("received error from external plugin: %v", err)
		}

		switch x := cr.Content.(type) {
		case *pb.CertificateResponse_Certificate:
			certRaw = x.Certificate
		case *pb.CertificateResponse_UserPrompt:
			fmt.Printf("%s\n", x.UserPrompt)
		case nil:
			// The field is not set.
		default:
			return nil, fmt.Errorf("Signature has unexpected type %T", x)
		}
	}

	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, fmt.Errorf("parse certificate error: %v", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certRaw},
		PrivateKey:  &externalSigner{cert.PublicKey, cfg, clusterAddress, path},
	}

	provider := &Authenticator{
		tlsCert: tlsCert,
	}

	return cache.setClient(cfg, provider), nil
}

type Authenticator struct {
	tlsCert *tls.Certificate
}

func (p *Authenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return nil, true, nil
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
