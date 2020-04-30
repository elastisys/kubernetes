package externalsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

var (
	certData = []byte(`-----BEGIN CERTIFICATE-----
MIIC6jCCAdSgAwIBAgIBCzALBgkqhkiG9w0BAQswIzEhMB8GA1UEAwwYMTAuMTMu
MTI5LjEwNkAxNDIxMzU5MDU4MB4XDTE1MDExNTIyMDEzMVoXDTE2MDExNTIyMDEz
MlowGzEZMBcGA1UEAxMQb3BlbnNoaWZ0LWNsaWVudDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAKtdhz0+uCLXw5cSYns9rU/XifFSpb/x24WDdrm72S/v
b9BPYsAStiP148buylr1SOuNi8sTAZmlVDDIpIVwMLff+o2rKYDicn9fjbrTxTOj
lI4pHJBH+JU3AJ0tbajupioh70jwFS0oYpwtneg2zcnE2Z4l6mhrj2okrc5Q1/X2
I2HChtIU4JYTisObtin10QKJX01CLfYXJLa8upWzKZ4/GOcHG+eAV3jXWoXidtjb
1Usw70amoTZ6mIVCkiu1QwCoa8+ycojGfZhvqMsAp1536ZcCul+Na+AbCv4zKS7F
kQQaImVrXdUiFansIoofGlw/JNuoKK6ssVpS5Ic3pgcCAwEAAaM1MDMwDgYDVR0P
AQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwCwYJ
KoZIhvcNAQELA4IBAQCKLREH7bXtXtZ+8vI6cjD7W3QikiArGqbl36bAhhWsJLp/
p/ndKz39iFNaiZ3GlwIURWOOKx3y3GA0x9m8FR+Llthf0EQ8sUjnwaknWs0Y6DQ3
jjPFZOpV3KPCFrdMJ3++E3MgwFC/Ih/N2ebFX9EcV9Vcc6oVWMdwT0fsrhu683rq
6GSR/3iVX1G/pmOiuaR0fNUaCyCfYrnI4zHBDgSfnlm3vIvN2lrsR/DQBakNL8DJ
HBgKxMGeUPoneBv+c8DMXIL0EhaFXRlBv9QW45/GiAIOuyFJ0i6hCtGZpJjq4OpQ
BRjCI+izPzFTjsxD4aORE+WOkyWFCGPWKfNejfw0
-----END CERTIFICATE-----`)
	keyData = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq12HPT64ItfDlxJiez2tT9eJ8VKlv/HbhYN2ubvZL+9v0E9i
wBK2I/Xjxu7KWvVI642LyxMBmaVUMMikhXAwt9/6jaspgOJyf1+NutPFM6OUjikc
kEf4lTcAnS1tqO6mKiHvSPAVLShinC2d6DbNycTZniXqaGuPaiStzlDX9fYjYcKG
0hTglhOKw5u2KfXRAolfTUIt9hcktry6lbMpnj8Y5wcb54BXeNdaheJ22NvVSzDv
RqahNnqYhUKSK7VDAKhrz7JyiMZ9mG+oywCnXnfplwK6X41r4BsK/jMpLsWRBBoi
ZWtd1SIVqewiih8aXD8k26gorqyxWlLkhzemBwIDAQABAoIBAD2XYRs3JrGHQUpU
FkdbVKZkvrSY0vAZOqBTLuH0zUv4UATb8487anGkWBjRDLQCgxH+jucPTrztekQK
aW94clo0S3aNtV4YhbSYIHWs1a0It0UdK6ID7CmdWkAj6s0T8W8lQT7C46mWYVLm
5mFnCTHi6aB42jZrqmEpC7sivWwuU0xqj3Ml8kkxQCGmyc9JjmCB4OrFFC8NNt6M
ObvQkUI6Z3nO4phTbpxkE1/9dT0MmPIF7GhHVzJMS+EyyRYUDllZ0wvVSOM3qZT0
JMUaBerkNwm9foKJ1+dv2nMKZZbJajv7suUDCfU44mVeaEO+4kmTKSGCGjjTBGkr
7L1ySDECgYEA5ElIMhpdBzIivCuBIH8LlUeuzd93pqssO1G2Xg0jHtfM4tz7fyeI
cr90dc8gpli24dkSxzLeg3Tn3wIj/Bu64m2TpZPZEIlukYvgdgArmRIPQVxerYey
OkrfTNkxU1HXsYjLCdGcGXs5lmb+K/kuTcFxaMOs7jZi7La+jEONwf8CgYEAwCs/
rUOOA0klDsWWisbivOiNPII79c9McZCNBqncCBfMUoiGe8uWDEO4TFHN60vFuVk9
8PkwpCfvaBUX+ajvbafIfHxsnfk1M04WLGCeqQ/ym5Q4sQoQOcC1b1y9qc/xEWfg
nIUuia0ukYRpl7qQa3tNg+BNFyjypW8zukUAC/kCgYB1/Kojuxx5q5/oQVPrx73k
2bevD+B3c+DYh9MJqSCNwFtUpYIWpggPxoQan4LwdsmO0PKzocb/ilyNFj4i/vII
NToqSc/WjDFpaDIKyuu9oWfhECye45NqLWhb/6VOuu4QA/Nsj7luMhIBehnEAHW+
GkzTKM8oD1PxpEG3nPKXYQKBgQC6AuMPRt3XBl1NkCrpSBy/uObFlFaP2Enpf39S
3OZ0Gv0XQrnSaL1kP8TMcz68rMrGX8DaWYsgytstR4W+jyy7WvZwsUu+GjTJ5aMG
77uEcEBpIi9CBzivfn7hPccE8ZgqPf+n4i6q66yxBJflW5xhvafJqDtW2LcPNbW/
bvzdmQKBgExALRUXpq+5dbmkdXBHtvXdRDZ6rVmrnjy4nI5bPw+1GqQqk6uAR6B/
F6NmLCQOO4PDG/cuatNHIr2FrwTmGdEL6ObLUGWn9Oer9gJhHVqqsY5I4sEPo4XX
stR0Yiw0buV6DL/moUO0HIM9Bjh96HJp+LxiIS6UCdIhMPp5HoQa
-----END RSA PRIVATE KEY-----`)
	validCert *tls.Certificate
)

func init() {
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		panic(err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}
	validCert = &cert
}

func TestClientCache(t *testing.T) {
	cache := newClientCache()

	cfg1 := map[string]string{
		"pathLib":   "/usr/local/lib/libykcs11.so",
		"slot-id":   "0",
		"object-id": "2",
	}
	cfg2 := map[string]string{
		"slot-id":   "0",
		"object-id": "2",
		"pathLib":   "/usr/local/lib/libykcs11.so",
	}
	cfg3 := map[string]string{
		"pathLib":   "/usr/local/lib/libykcs11.so",
		"slot-id":   "1",
		"object-id": "2",
	}
	if _, ok := cache.getClient(cfg1); ok {
		t.Fatalf("got client before putting one in the cache")
	}
	assertCacheLen(t, cache, 0)

	cli1 := new(Authenticator)
	cli2 := new(Authenticator)
	cli3 := new(Authenticator)

	gotcli := cache.setClient(cfg1, cli1)
	if cli1 != gotcli {
		t.Fatalf("set first client and got a different one")
	}
	assertCacheLen(t, cache, 1)

	gotcli = cache.setClient(cfg2, cli2)
	if cli1 != gotcli {
		t.Fatalf("set a second client and didn't get the first")
	}
	assertCacheLen(t, cache, 1)

	gotcli = cache.setClient(cfg3, cli3)
	if cli1 == gotcli {
		t.Fatalf("set a third client and got the first")
	}
	if cli3 != gotcli {
		t.Fatalf("set third client and got a different one")
	}
	assertCacheLen(t, cache, 2)
}

func assertCacheLen(t *testing.T, cache *clientCache, length int) {
	t.Helper()
	if len(cache.cache) != length {
		t.Errorf("expected cache length %d got %d", length, len(cache.cache))
	}
}

// func TestTLSCredentials(t *testing.T) {
// 	now := time.Now()

// 	certPool := x509.NewCertPool()
// 	cert, key := genClientCert(t)
// 	if !certPool.AppendCertsFromPEM(cert) {
// 		t.Fatal("failed to add client cert to CertPool")
// 	}

// 	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Fprintln(w, "ok")
// 	}))
// 	server.TLS = &tls.Config{
// 		ClientAuth: tls.RequireAndVerifyClientCert,
// 		ClientCAs:  certPool,
// 	}
// 	server.StartTLS()
// 	defer server.Close()

// 	// clusterAddress := "a" // string,
// 	cfg := map[string]string{
// 		"pathLib":   "/usr/local/lib/libykcs11.so",
// 		"slot-id":   "0",
// 		"object-id": "2",
// 	}
// 	// persister restclient.AuthProviderConfigPersister

// 	// a, err := newPKCS11AuthProvider(clusterAddress, cfg, nil)

// 	// auth := Authenticator(a)
// 	// a, err := newAuthenticator(newCache(), &api.ExecConfig{
// 	// 	Command:    "./testdata/test-plugin.sh",
// 	// 	APIVersion: "client.authentication.k8s.io/v1alpha1",
// 	// })
// 	// if err != nil {
// 	// 	t.Fatal(err)
// 	// }
// 	// var output *clientauthentication.ExecCredential
// 	// a.environ = func() []string {
// 	// 	data, err := runtime.Encode(codecs.LegacyCodec(a.group), output)
// 	// 	if err != nil {
// 	// 		t.Fatal(err)
// 	// 	}
// 	// 	return []string{"TEST_OUTPUT=" + string(data)}
// 	// }
// 	// a.now = func() time.Time { return now }
// 	// a.stderr = ioutil.Discard

// 	// We're not interested in server's cert, this test is about client cert.
// 	// tc := &transport.Config{TLS: transport.TLSConfig{Insecure: true}}
// 	tc := &transport.Config{}

// 	certx509, certErr := x509.ParseCertificate(cert)
// 	if certErr != nil {
// 		fmt.Printf("Error: %s\n", certErr)
// 	}

// 	tlsCert := &tls.Certificate{
// 		Certificate: [][]byte{cert},
// 		PrivateKey:  &externalSigner{certx509.PublicKey, cfg},
// 	}

// 	a := Authenticator{
// 		tlsCert: tlsCert,
// 	}
// 	// tc := &transport.Config{}
// 	if err := a.UpdateTransportConfig(tc); err != nil {
// 		t.Fatal(err)
// 	}

// 	get := func(t *testing.T, desc string, wantErr bool) {
// 		t.Run(desc, func(t *testing.T) {
// 			tlsCfg, err := transport.TLSConfigFor(tc)
// 			if err != nil {
// 				t.Fatal("TLSConfigFor:", err)
// 			}
// 			client := http.Client{
// 				Transport: &http.Transport{TLSClientConfig: tlsCfg},
// 			}
// 			resp, err := client.Get(server.URL)
// 			switch {
// 			case err != nil && !wantErr:
// 				t.Errorf("got client.Get error: %q, want nil", err)
// 			case err == nil && wantErr:
// 				t.Error("got nil client.Get error, want non-nil")
// 			}
// 			if err == nil {
// 				resp.Body.Close()
// 			}
// 		})
// 	}

// 	_ = &clientauthentication.ExecCredential{
// 		Status: &clientauthentication.ExecCredentialStatus{
// 			ClientCertificateData: string(cert),
// 			ClientKeyData:         string(key),
// 			ExpirationTimestamp:   &v1.Time{now.Add(time.Hour)},
// 		},
// 	}
// 	get(t, "valid TLS cert", false)

// 	// Advance time to force re-exec.
// 	nCert, nKey := genClientCert(t)
// 	now = now.Add(time.Hour * 2)
// 	_ = &clientauthentication.ExecCredential{
// 		Status: &clientauthentication.ExecCredentialStatus{
// 			ClientCertificateData: string(nCert),
// 			ClientKeyData:         string(nKey),
// 			ExpirationTimestamp:   &v1.Time{now.Add(time.Hour)},
// 		},
// 	}
// 	get(t, "untrusted TLS cert", true)

// 	now = now.Add(time.Hour * 2)
// 	_ = &clientauthentication.ExecCredential{
// 		Status: &clientauthentication.ExecCredentialStatus{
// 			ClientCertificateData: string(cert),
// 			ClientKeyData:         string(key),
// 			ExpirationTimestamp:   &v1.Time{now.Add(time.Hour)},
// 		},
// 	}
// 	get(t, "valid TLS cert again", false)
// }

// genClientCert generates an x509 certificate for testing. Certificate and key
// are returned in PEM encoding. The generated cert expires in 24 hours.
func genClientCert(t *testing.T) ([]byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw})
}
