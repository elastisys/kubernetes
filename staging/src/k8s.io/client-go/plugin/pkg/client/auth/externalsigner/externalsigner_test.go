package externalsigner

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	restclient "k8s.io/client-go/rest"
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
	x509Cert *x509.Certificate
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
	x509Cert = cert.Leaf
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

func TestHelperProcessSign(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 {
		t.Skip()
	}

	response := os.Args[2]
	// signRequest := os.Args[5]
	signRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
	fmt.Fprintf(os.Stderr, "Args: %s\n", signRequest)

	type SignMessage struct {
		APIVersion     string            `json:"apiVersion"`
		Kind           string            `json:"kind"`
		Configuration  map[string]string `json:"configuration"`
		Digest         string            `json:"digest"`
		SignerOptsType string            `json:"signerOptsType"`
		SignerOpts     string            `json:"signerOpts"`
	}

	var signMessage SignMessage

	err := json.Unmarshal([]byte(signRequest), &signMessage)
	if err != nil {
		fmt.Printf("unmarshal error: %v", err)
		t.Fatal(err)
		return
	}

	if signMessage.Configuration["pathLib"] == "" {
		t.Fatal(err)
		return
	}

	fmt.Fprintf(os.Stdout, response)
	os.Exit(0)
}

func TestSign(t *testing.T) {
	tests := []struct {
		name     string
		cfg      map[string]string
		response string
		wantErr  bool
	}{
		{
			name: "correct",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug==\"}",
		},
		{
			name:     "missingConfig",
			cfg:      map[string]string{},
			response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug==\"}",
			wantErr:  true,
		},
		{
			name: "missingSignature",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\"}",
			wantErr:  true,
		},
		{
			name: "malformedSignature",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug\"}",
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := externalSigner{x509Cert.PublicKey, test.cfg}

			var rand io.Reader
			var digest []byte

			signerOptsString := "{\"SaltLength\":-1,\"Hash\":5}"
			var pSSOptions rsa.PSSOptions
			err := json.Unmarshal([]byte(signerOptsString), &pSSOptions)
			if err != nil {
				fmt.Printf("Unmarshal error: %s\n", err)
			}

			rand = nil
			digest = nil

			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcessSign", test.response, "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				return cmd
			}

			signature, err := signer.Sign(rand, digest, &pSSOptions)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				if !test.wantErr {
					t.Fatal(err)
				}
				return
			}
			if signature == nil || string(signature) == "" {
				fmt.Printf("Signature is nil\n")
				if !test.wantErr {
					t.Fatal(err)
				}
				return
			}
			if test.wantErr {
				t.Fatal("expected error")
			}
		})
	}
}

func TestHelperProcessGetCertificate(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 {
		t.Skip()
	}

	response := os.Args[2]
	certificateRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
	// certificateRequest := os.Args[5]
	fmt.Fprintf(os.Stderr, "Args: %s\n", certificateRequest)
	fmt.Fprintf(os.Stdout, response)
	os.Exit(0)
}

func TestGetCertificate(t *testing.T) {
	tests := []struct {
		name     string
		cfg      map[string]string
		response string
		wantErr  bool
	}{
		{
			name: "correct",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5pa3ViZUNBMB4XDTIwMDQxMzEzMDQyNVoXDTIxMDQxNDEzMDQyNVowMTEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrMKV03/EKwgpOBIDvRFOxDEFBcCxuwrWva5GiZWh3UhLRTDZfeFgxeMYUo/bX0o1D/aDCgd0k1eTmA6ANchAldjjnxsvEiWZDWdu9tDQnmHP3dM4Zp14k7KrfNkG50eFXzIl9oIuAo5GDaeXydTufniLOaKor1uuk322Ms7rwci8DOz6LTXG6n6J8XL2U5b3gTFyBdkt08Uh0N/NhnuotOLyuAeGjJuTriHemyv0jT09twbEQtKhIvu4tyJ/C421PX+J3tgR63lkzQ3C98D5p1sYJseEQa8GXtQ9he08Uqh51roAvmoPhxguA7AuAgy/vAV1sfpCtei6Q68T4PrKDAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAO9l9BxUB1UIACOvs23ONdsd71iKZczyC+D5fp4O159+azMfCisek2DaJHJpWPeZQEl/auGsMj15bEV+rECqtNpngHE2ywee3iJfWCnv41mGx+y5KcDDfl5C1lHxg+JYbIDc4KSSBdK6mdn0TvN6sl5bpT6wyxlxD2ln5z2B+NUkggSknljrm/nf7/nv5BWK+i4oG1XsuGhrGy8Yi4TFO5s2COh8ce3ToERv9BdxN/5N2UPNVOpM3dTPLgntzPIqgiLiGe0asENIrb8uwqVZdIGx2C3Blemv0kwwISWVLs+ouBJHS07uAlEfwDIaxn0z70We52oMM2vM0lR6orvgMvQ==\"}",
		},
		{
			name: "missingPathExec",
			cfg: map[string]string{
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5pa3ViZUNBMB4XDTIwMDQxMzEzMDQyNVoXDTIxMDQxNDEzMDQyNVowMTEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrMKV03/EKwgpOBIDvRFOxDEFBcCxuwrWva5GiZWh3UhLRTDZfeFgxeMYUo/bX0o1D/aDCgd0k1eTmA6ANchAldjjnxsvEiWZDWdu9tDQnmHP3dM4Zp14k7KrfNkG50eFXzIl9oIuAo5GDaeXydTufniLOaKor1uuk322Ms7rwci8DOz6LTXG6n6J8XL2U5b3gTFyBdkt08Uh0N/NhnuotOLyuAeGjJuTriHemyv0jT09twbEQtKhIvu4tyJ/C421PX+J3tgR63lkzQ3C98D5p1sYJseEQa8GXtQ9he08Uqh51roAvmoPhxguA7AuAgy/vAV1sfpCtei6Q68T4PrKDAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAO9l9BxUB1UIACOvs23ONdsd71iKZczyC+D5fp4O159+azMfCisek2DaJHJpWPeZQEl/auGsMj15bEV+rECqtNpngHE2ywee3iJfWCnv41mGx+y5KcDDfl5C1lHxg+JYbIDc4KSSBdK6mdn0TvN6sl5bpT6wyxlxD2ln5z2B+NUkggSknljrm/nf7/nv5BWK+i4oG1XsuGhrGy8Yi4TFO5s2COh8ce3ToERv9BdxN/5N2UPNVOpM3dTPLgntzPIqgiLiGe0asENIrb8uwqVZdIGx2C3Blemv0kwwISWVLs+ouBJHS07uAlEfwDIaxn0z70We52oMM2vM0lR6orvgMvQ==\"}",
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var clusterAddress string
			var persister restclient.AuthProviderConfigPersister

			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcessGetCertificate", test.response, "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				return cmd
			}

			// var authenticator *Authenticator
			// var err error

			// provider, err := newExternalSignerAuthProvider(clusterAddress, test.cfg, persister)
			_, err := newExternalSignerAuthProvider(clusterAddress, test.cfg, persister)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				if !test.wantErr {
					t.Fatal(err)
				}
				return
			}
			if test.wantErr {
				t.Fatal("expected error")
			}

			// authenticator = *provider

			// if authenticator.tlsCert == nil {
			// 	fmt.Printf("Error: %s\n", err)
			// }

			// fmt.Printf("Stderr: %s\n", stderr.String())
			// fmt.Printf("Stdin: %s\n", stdin)
			// fmt.Printf("Stdout: %s\n", stdout)

			// (restclient.AuthProvider, error) :=
		})
	}
}

func TestHelperProcessGetCertificateRSA(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 {
		t.Skip()
	}

	response := os.Args[2]
	certificateRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
	fmt.Fprintf(os.Stderr, "Args: %s\n", certificateRequest)
	fmt.Fprintf(os.Stdout, response)
	os.Exit(0)
}

func TestHelperProcessSignRSA(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 {
		t.Skip()
	}

	response := os.Args[2]
	// signRequest := os.Args[5]
	signRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
	fmt.Fprintf(os.Stderr, "Args: %s\n", signRequest)

	type SignMessage struct {
		APIVersion     string            `json:"apiVersion"`
		Kind           string            `json:"kind"`
		Configuration  map[string]string `json:"configuration"`
		Digest         string            `json:"digest"`
		SignerOptsType string            `json:"signerOptsType"`
		SignerOpts     string            `json:"signerOpts"`
	}

	var signMessage SignMessage

	err := json.Unmarshal([]byte(signRequest), &signMessage)
	if err != nil {
		fmt.Printf("unmarshal error: %v", err)
		t.Fatal(err)
		return
	}

	if signMessage.Configuration["pathLib"] == "" {
		t.Fatal(err)
		return
	}

	fmt.Fprintf(os.Stdout, response)
	os.Exit(0)
}

func TestRoundTrip(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}

	// err = privKey.Validate()
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// pubDER := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)

	// pubBlock := pem.Block{
	// 	Type:    "PUBLIC KEY",
	// 	Headers: nil,
	// 	Bytes:   pubDER,
	// }

	// pubPEM := pem.EncodeToMemory(&pubBlock)

	// fmt.Printf("pubPEM: %s\n", b64.StdEncoding.EncodeToString(pubPEM))

	// privDER := x509.MarshalPKCS1PrivateKey(privKey)

	// privBlock := pem.Block{
	// 	Type:    "RSA PRIVATE KEY",
	// 	Headers: nil,
	// 	Bytes:   privDER,
	// }

	// privatePEM := pem.EncodeToMemory(&privBlock)

	// fmt.Printf("privatePEM: %s\n", b64.StdEncoding.EncodeToString(privatePEM))

	// block, _ := pem.Decode([]byte(pubPEM))
	// if block == nil {
	// 	fmt.Println("Invalid PEM Block")
	// 	return
	// }

	message := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

	opts := rsa.PSSOptions{
		SaltLength: -1,
		Hash:       crypto.SHA256.HashFunc(),
	}

	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privKey, newhash, hashed, &opts)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Company, INC."},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Company, INC."},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	b, err := json.Marshal(cert)
	if err != nil {
		fmt.Errorf("marshal error: %v", err)
	}
	fmt.Printf("Certificate: %s\n", string(b))

	tests := []struct {
		name                   string
		cfg                    map[string]string
		responseGetCertificate string
		responseSign           string
		wantErr                bool
	}{
		{
			name: "correct",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			responseGetCertificate: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"" + b64.StdEncoding.EncodeToString(certBytes) + "\"}",
			responseSign:           "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"" + b64.StdEncoding.EncodeToString(signature) + "\"}",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var clusterAddress string
			var persister restclient.AuthProviderConfigPersister

			execCommand = func(command string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestHelperProcessGetCertificateRSA", test.responseGetCertificate, "--", command}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				return cmd
			}

			auth, err := newExternalSignerAuthProvider(clusterAddress, test.cfg, persister)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				if !test.wantErr {
					t.Fatal(err)
				}
				return
			}

			if test.wantErr {
				t.Fatal("expected error")
			}

			b, err := json.Marshal(auth)
			if err != nil {
				fmt.Errorf("marshal error: %v", err)
			}
			fmt.Printf("authenticator: %s\n", string(b))

			// signer := externalSigner{x509Cert.PublicKey, test.cfg}
			signer := externalSigner{privKey.PublicKey, test.cfg}

			var rand io.Reader
			var digest []byte

			signerOptsString := "{\"SaltLength\":-1,\"Hash\":5}"
			var pSSOptions rsa.PSSOptions
			err = json.Unmarshal([]byte(signerOptsString), &pSSOptions)
			if err != nil {
				fmt.Printf("Unmarshal error: %s\n", err)
			}

			rand = nil
			digest = nil

			// execCommand = test.execCommand
			execCommand = func(command string, args ...string) *exec.Cmd {
				csSign := []string{"-test.run=TestHelperProcessSignRSA", test.responseSign, "--", command}
				csSign = append(csSign, args...)
				cmdSign := exec.Command(os.Args[0], csSign...)
				return cmdSign
			}

			signatureExt, err := signer.Sign(rand, digest, &pSSOptions)
			fmt.Printf("signatureExt: %s\n", b64.StdEncoding.EncodeToString(signatureExt))

			// err = rsa.VerifyPSS(&privKey.PublicKey, newhash, hashed, signature, &opts)
			err = rsa.VerifyPSS(&privKey.PublicKey, newhash, hashed, signatureExt, &opts)
			if err != nil {
				fmt.Println(err)
				return
			}

			fmt.Println("Successfully verified message with signature and public key")
		})
	}
}
