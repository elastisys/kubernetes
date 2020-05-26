package externalsigner

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"testing"

	b64 "encoding/base64"

	mock "k8s.io/client-go/plugin/pkg/client/auth/externalsigner/testing"
	pb "k8s.io/client-go/plugin/pkg/client/auth/externalsigner/v1alpha1"
	restclient "k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/util/uuid"
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
	// fmt.Printf("\n!!!! INIT !!!!\n")
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

type testSocket struct {
	path     string
	endpoint string
}

// newEndpoint constructs a unique name for a Linux Abstract Socket to be used in a test.
// This package uses Linux Domain Sockets to remove the need for clean-up of socket files.
func newEndpoint() *testSocket {
	p := fmt.Sprintf("@%s.sock", uuid.NewUUID())

	return &testSocket{
		path:     p,
		endpoint: fmt.Sprintf("unix:///%s", p),
	}
}

// type server struct {
// 	mock.UnimplementedExternalSignerServiceServer
// }

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

func TestSign(t *testing.T) {
	tests := []struct {
		name         string
		cfg          map[string]string
		signatureStr string
		wantErr      bool
	}{
		{
			name: "correct",
			cfg: map[string]string{
				"pathExec": "/path/to/externalSigner",
				"pathLib":  "/path/to/library.so",
				"slotId":   "0",
				"objectId": "2",
			},
			signatureStr: "w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug==",
		},
		{
			name:         "missingConfig",
			cfg:          map[string]string{},
			signatureStr: "w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug==",
			wantErr:      true,
		},
		{
			name: "missingSignature",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			signatureStr: "",
			wantErr:      true,
		},
		{
			name: "malformedSignature",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			signatureStr: "w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug",
			wantErr:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := externalSigner{x509Cert.PublicKey, test.cfg, "socketPath"}

			var rand io.Reader
			var digest []byte

			pSSOptions := rsa.PSSOptions{
				SaltLength: -1,
				Hash:       crypto.SHA256.HashFunc(),
			}

			rand = nil
			digest = nil

			s := newEndpoint()
			signatureByte, _ := b64.StdEncoding.DecodeString(test.signatureStr)
			f, err := mock.NewExternalSignerPlugin(s.path, pb.CertificateResponse{}, pb.SignatureResponse{Signature: signatureByte})
			f.Start()
			defer f.CleanUp()
			signer.socketPath = s.path

			signature, err := signer.Sign(rand, digest, &pSSOptions)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				if !test.wantErr {
					t.Fatal(err)
				}
				return
			}
			if signature == nil || string(signature) == "" {
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

func TestGetCertificate(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]string
		// response string
		certificateStr string
		wantErr        bool
	}{
		{
			name: "correct",
			cfg: map[string]string{
				"pathExec":  "/path/to/externalSigner",
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			// response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5pa3ViZUNBMB4XDTIwMDQxMzEzMDQyNVoXDTIxMDQxNDEzMDQyNVowMTEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrMKV03/EKwgpOBIDvRFOxDEFBcCxuwrWva5GiZWh3UhLRTDZfeFgxeMYUo/bX0o1D/aDCgd0k1eTmA6ANchAldjjnxsvEiWZDWdu9tDQnmHP3dM4Zp14k7KrfNkG50eFXzIl9oIuAo5GDaeXydTufniLOaKor1uuk322Ms7rwci8DOz6LTXG6n6J8XL2U5b3gTFyBdkt08Uh0N/NhnuotOLyuAeGjJuTriHemyv0jT09twbEQtKhIvu4tyJ/C421PX+J3tgR63lkzQ3C98D5p1sYJseEQa8GXtQ9he08Uqh51roAvmoPhxguA7AuAgy/vAV1sfpCtei6Q68T4PrKDAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAO9l9BxUB1UIACOvs23ONdsd71iKZczyC+D5fp4O159+azMfCisek2DaJHJpWPeZQEl/auGsMj15bEV+rECqtNpngHE2ywee3iJfWCnv41mGx+y5KcDDfl5C1lHxg+JYbIDc4KSSBdK6mdn0TvN6sl5bpT6wyxlxD2ln5z2B+NUkggSknljrm/nf7/nv5BWK+i4oG1XsuGhrGy8Yi4TFO5s2COh8ce3ToERv9BdxN/5N2UPNVOpM3dTPLgntzPIqgiLiGe0asENIrb8uwqVZdIGx2C3Blemv0kwwISWVLs+ouBJHS07uAlEfwDIaxn0z70We52oMM2vM0lR6orvgMvQ==\"}",
			certificateStr: "MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5pa3ViZUNBMB4XDTIwMDQxMzEzMDQyNVoXDTIxMDQxNDEzMDQyNVowMTEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrMKV03/EKwgpOBIDvRFOxDEFBcCxuwrWva5GiZWh3UhLRTDZfeFgxeMYUo/bX0o1D/aDCgd0k1eTmA6ANchAldjjnxsvEiWZDWdu9tDQnmHP3dM4Zp14k7KrfNkG50eFXzIl9oIuAo5GDaeXydTufniLOaKor1uuk322Ms7rwci8DOz6LTXG6n6J8XL2U5b3gTFyBdkt08Uh0N/NhnuotOLyuAeGjJuTriHemyv0jT09twbEQtKhIvu4tyJ/C421PX+J3tgR63lkzQ3C98D5p1sYJseEQa8GXtQ9he08Uqh51roAvmoPhxguA7AuAgy/vAV1sfpCtei6Q68T4PrKDAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAO9l9BxUB1UIACOvs23ONdsd71iKZczyC+D5fp4O159+azMfCisek2DaJHJpWPeZQEl/auGsMj15bEV+rECqtNpngHE2ywee3iJfWCnv41mGx+y5KcDDfl5C1lHxg+JYbIDc4KSSBdK6mdn0TvN6sl5bpT6wyxlxD2ln5z2B+NUkggSknljrm/nf7/nv5BWK+i4oG1XsuGhrGy8Yi4TFO5s2COh8ce3ToERv9BdxN/5N2UPNVOpM3dTPLgntzPIqgiLiGe0asENIrb8uwqVZdIGx2C3Blemv0kwwISWVLs+ouBJHS07uAlEfwDIaxn0z70We52oMM2vM0lR6orvgMvQ==",
		},
		{
			name: "missingPathExec",
			cfg: map[string]string{
				"pathLib":   "/path/to/library.so",
				"slot-id":   "0",
				"object-id": "2",
			},
			// response: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5pa3ViZUNBMB4XDTIwMDQxMzEzMDQyNVoXDTIxMDQxNDEzMDQyNVowMTEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrMKV03/EKwgpOBIDvRFOxDEFBcCxuwrWva5GiZWh3UhLRTDZfeFgxeMYUo/bX0o1D/aDCgd0k1eTmA6ANchAldjjnxsvEiWZDWdu9tDQnmHP3dM4Zp14k7KrfNkG50eFXzIl9oIuAo5GDaeXydTufniLOaKor1uuk322Ms7rwci8DOz6LTXG6n6J8XL2U5b3gTFyBdkt08Uh0N/NhnuotOLyuAeGjJuTriHemyv0jT09twbEQtKhIvu4tyJ/C421PX+J3tgR63lkzQ3C98D5p1sYJseEQa8GXtQ9he08Uqh51roAvmoPhxguA7AuAgy/vAV1sfpCtei6Q68T4PrKDAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAO9l9BxUB1UIACOvs23ONdsd71iKZczyC+D5fp4O159+azMfCisek2DaJHJpWPeZQEl/auGsMj15bEV+rECqtNpngHE2ywee3iJfWCnv41mGx+y5KcDDfl5C1lHxg+JYbIDc4KSSBdK6mdn0TvN6sl5bpT6wyxlxD2ln5z2B+NUkggSknljrm/nf7/nv5BWK+i4oG1XsuGhrGy8Yi4TFO5s2COh8ce3ToERv9BdxN/5N2UPNVOpM3dTPLgntzPIqgiLiGe0asENIrb8uwqVZdIGx2C3Blemv0kwwISWVLs+ouBJHS07uAlEfwDIaxn0z70We52oMM2vM0lR6orvgMvQ==\"}",
			certificateStr: "MIIDADCCAeigAwIBAgIBAjANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5pa3ViZUNBMB4XDTIwMDQxMzEzMDQyNVoXDTIxMDQxNDEzMDQyNVowMTEXMBUGA1UEChMOc3lzdGVtOm1hc3RlcnMxFjAUBgNVBAMTDW1pbmlrdWJlLXVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrMKV03/EKwgpOBIDvRFOxDEFBcCxuwrWva5GiZWh3UhLRTDZfeFgxeMYUo/bX0o1D/aDCgd0k1eTmA6ANchAldjjnxsvEiWZDWdu9tDQnmHP3dM4Zp14k7KrfNkG50eFXzIl9oIuAo5GDaeXydTufniLOaKor1uuk322Ms7rwci8DOz6LTXG6n6J8XL2U5b3gTFyBdkt08Uh0N/NhnuotOLyuAeGjJuTriHemyv0jT09twbEQtKhIvu4tyJ/C421PX+J3tgR63lkzQ3C98D5p1sYJseEQa8GXtQ9he08Uqh51roAvmoPhxguA7AuAgy/vAV1sfpCtei6Q68T4PrKDAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAO9l9BxUB1UIACOvs23ONdsd71iKZczyC+D5fp4O159+azMfCisek2DaJHJpWPeZQEl/auGsMj15bEV+rECqtNpngHE2ywee3iJfWCnv41mGx+y5KcDDfl5C1lHxg+JYbIDc4KSSBdK6mdn0TvN6sl5bpT6wyxlxD2ln5z2B+NUkggSknljrm/nf7/nv5BWK+i4oG1XsuGhrGy8Yi4TFO5s2COh8ce3ToERv9BdxN/5N2UPNVOpM3dTPLgntzPIqgiLiGe0asENIrb8uwqVZdIGx2C3Blemv0kwwISWVLs+ouBJHS07uAlEfwDIaxn0z70We52oMM2vM0lR6orvgMvQ==",
			wantErr:        true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Log(test.response)
			var clusterAddress string
			var persister restclient.AuthProviderConfigPersister

			// execCommand = func(command string, args ...string) *exec.Cmd {
			// 	cs := []string{"-test.run=TestHelperProcessGetCertificate", certTest.response, "--", command}
			// 	cs = append(cs, args...)
			// 	cmd := exec.Command(os.Args[0], cs...)
			// 	return cmd
			// }

			s := newEndpoint()
			certificateByte, _ := b64.StdEncoding.DecodeString(test.certificateStr)
			f, err := mock.NewExternalSignerPlugin(s.path, pb.CertificateResponse{Certificate: certificateByte}, pb.SignatureResponse{})
			f.Start()
			defer f.CleanUp()
			signer.socketPath = s.path

			provider, err := newExternalSignerAuthProvider(clusterAddress, test.cfg, persister)
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

			var authenticator *Authenticator
			authenticator = provider.(*Authenticator)

			if authenticator.tlsCert == nil {
				t.Fatal(err)
				// fmt.Printf("Error: %s\n", err)
			}

			// b, err := json.Marshal(authenticator.tlsCert)
			// if err != nil {
			// 	fmt.Printf("marshal error: %v", err)
			// }
			// fmt.Printf("TLS certificate: %s\n", string(b))
		})
	}
}

// func TestHelperProcessSignatureVerification(t *testing.T) {
// 	// fmt.Fprintf(os.Stderr, "HELPER: TestHelperProcess, args: %d\n", len(os.Args))

// 	if len(os.Args) < 5 {
// 		t.Skip()
// 	}

// 	request := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
// 	fmt.Fprintf(os.Stderr, "Env: %s\n", request)

// 	type RequestMessage struct {
// 		APIVersion string `json:"apiVersion"`
// 		Kind       string `json:"kind"`
// 	}

// 	var requestMessage RequestMessage

// 	err := json.Unmarshal([]byte(request), &requestMessage)
// 	if err != nil {
// 		// fmt.Printf("unmarshal error: %v", err)
// 		t.Fatalf("Unmarshal error: %s\n", err)
// 		return
// 	}

// 	if requestMessage.Kind == "" {
// 		t.Fatal(err)
// 		return
// 	}

// 	var response string

// 	switch requestMessage.Kind {
// 	case "Certificate":
// 		response = os.Args[2]
// 	case "Sign":
// 		response = os.Args[3]
// 	default:
// 		t.Fatalf("Response for Kind %s is not implemented", requestMessage.Kind)
// 		return
// 	}

// 	// fmt.Fprintf(os.Stderr, "%s\n", response)
// 	fmt.Fprintf(os.Stdout, response)
// 	os.Exit(0)
// }

// func TestHelperProcessSignatureVerificationGetCertificate(t *testing.T) {
// 	// fmt.Fprintf(os.Stderr, "HELPER: TestHelperProcessSignatureVerificationGetCertificate, args: %d\n", len(os.Args))
// 	// t.Helper()
// 	if len(os.Args) < 5 {
// 		t.Skip()
// 	}

// 	response := os.Args[2]
// 	// signatureRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
// 	// fmt.Fprintf(os.Stderr, "Args: %s\n", signatureRequest)
// 	fmt.Fprintf(os.Stdout, response)
// 	os.Exit(0)
// }

// func TestHelperProcessSignatureVerificationSign(t *testing.T) {
// 	// fmt.Fprintf(os.Stderr, "HELPER: TestHelperProcessSignatureVerificationSign, args: %d\n", len(os.Args))
// 	// t.Helper()
// 	if len(os.Args) < 5 {
// 		t.Skip()
// 	}

// 	response := os.Args[2]
// 	signRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
// 	// fmt.Fprintf(os.Stderr, "Args: %s\n", signRequest)

// 	type SignMessage struct {
// 		APIVersion     string            `json:"apiVersion"`
// 		Kind           string            `json:"kind"`
// 		Configuration  map[string]string `json:"configuration"`
// 		Digest         string            `json:"digest"`
// 		SignerOptsType string            `json:"signerOptsType"`
// 		SignerOpts     string            `json:"signerOpts"`
// 	}

// 	var signMessage SignMessage

// 	err := json.Unmarshal([]byte(signRequest), &signMessage)
// 	if err != nil {
// 		// fmt.Printf("unmarshal error: %v", err)
// 		t.Fatalf("Unmarshal error: %s\n", err)
// 		return
// 	}

// 	digest, err := b64.StdEncoding.DecodeString(signMessage.Digest)

// 	fmt.Printf("DIGEST: %s\n", string(digest))

// 	if signMessage.Configuration["pathLib"] == "" {
// 		t.Fatal(err)
// 		return
// 	}

// 	fmt.Fprintf(os.Stdout, response)
// 	os.Exit(0)
// }

// func TestSignatureVerification(t *testing.T) {

// 	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	message := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

// 	opts := rsa.PSSOptions{
// 		SaltLength: -1,
// 		Hash:       crypto.SHA256.HashFunc(),
// 	}

// 	PSSmessage := message
// 	newhash := crypto.SHA256
// 	pssh := newhash.New()
// 	pssh.Write(PSSmessage)
// 	hashed := pssh.Sum(nil)

// 	signature, err := rsa.SignPSS(rand.Reader, privKey, newhash, hashed, &opts)

// 	certificate := &x509.Certificate{
// 		SerialNumber: big.NewInt(2019),
// 		Subject: pkix.Name{
// 			Organization: []string{"Company, INC."},
// 		},
// 		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().AddDate(10, 0, 0),
// 		SubjectKeyId: []byte{1, 2, 3, 4, 6},
// 		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
// 		KeyUsage:     x509.KeyUsageDigitalSignature,
// 	}

// 	ca := &x509.Certificate{
// 		SerialNumber: big.NewInt(2019),
// 		Subject: pkix.Name{
// 			Organization: []string{"Company, INC."},
// 		},
// 		NotBefore:             time.Now(),
// 		NotAfter:              time.Now().AddDate(10, 0, 0),
// 		IsCA:                  true,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
// 		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
// 		BasicConstraintsValid: true,
// 	}

// 	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, ca, privKey.Public(), caPrivKey)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	tests := []struct {
// 		name                   string
// 		cfg                    map[string]string
// 		responseGetCertificate string
// 		responseSign           string
// 		wantCertErr            bool
// 		wantSignErr            bool
// 		wantVerifErr           bool
// 	}{
// 		{
// 			name: "verificationShouldSucceed",
// 			cfg: map[string]string{
// 				"pathExec":  "/path/to/externalSigner",
// 				"pathLib":   "/path/to/library.so",
// 				"slot-id":   "0",
// 				"object-id": "2",
// 			},
// 			responseGetCertificate: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"" + b64.StdEncoding.EncodeToString(certBytes) + "\"}",
// 			responseSign:           "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"" + b64.StdEncoding.EncodeToString(signature) + "\"}",
// 		},
// 		{
// 			name: "verificationShouldFail",
// 			cfg: map[string]string{
// 				"pathExec":  "/path/to/externalSigner",
// 				"pathLib":   "/path/to/library.so",
// 				"slot-id":   "0",
// 				"object-id": "2",
// 			},
// 			responseGetCertificate: "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"" + b64.StdEncoding.EncodeToString(certBytes) + "\"}",
// 			responseSign:           "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"18IHTFq1MHoF7cvyQETVFipuKTGWQdmCYUIUggHEVGMEuJ5l/8wM2vABgRIxJdv5q5Bg7gCZvmAXtOO4/uP7bq7cazZ7TSuVNFPgsfLx0mKUvm1SLVpRkqQPah8CNt5YsH+WxthTFg/U86pD+Mi7j1kkB8PXnB23Pe1H2nmFPjNxneehCZSpyKFD9TRXwlkud0jQdwlFZzh9cZSZ8blNQBN8iBCJ8/KpLgpvxq7DYQW/mLzaieBg1OKwUfCCPAwhbaxjWygzzztOgQ15aVX9fVq53iUuhhB0vjX3I2kXEIdJXlH//UwhQZWQuXFI8F689vfkyY3psJpFFAqLKxXAbw==\"}",
// 			wantVerifErr:           true,
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			t.Log(test.responseGetCertificate)
// 			var clusterAddress string
// 			var persister restclient.AuthProviderConfigPersister

// 			// fmt.Printf("Before set execCommand\n")
// 			execCommand = func(command string, args ...string) *exec.Cmd {
// 				cs := []string{"-test.run=TestHelperProcessSignatureVerificationGetCertificate", test.responseGetCertificate, "--", command}
// 				// cs := []string{"-test.run=TestHelperProcessSignatureVerification", test.responseGetCertificate, test.responseSign, "--", command}
// 				cs = append(cs, args...)
// 				cmd := exec.Command(os.Args[0], cs...)
// 				return cmd
// 			}
// 			// fmt.Printf("After set execCommand\n")
// 			// helperResponse = *test.responseGetCertificate
// 			// fmt.Fprintf(os.Stderr, "TEST: response: %v\n", helperResponse)

// 			provider, err := newExternalSignerAuthProvider(clusterAddress, test.cfg, persister)
// 			if err != nil {
// 				fmt.Printf("Error: %s\n", err)
// 				if !test.wantCertErr {
// 					t.Fatal(err)
// 				}
// 				return
// 			}
// 			// fmt.Printf("After newExternalSignerAuthProvider\n")

// 			if test.wantCertErr {
// 				t.Fatal("expected get certificate error")
// 			}

// 			var authenticator *Authenticator
// 			authenticator = provider.(*Authenticator)

// 			if authenticator.tlsCert == nil {
// 				t.Fatalf("Error: %s\n", err)
// 				return
// 			}

// 			certParsed, err := x509.ParseCertificate(authenticator.tlsCert.Certificate[0])
// 			if err != nil {
// 				t.Fatalf("parse certificate error: %v", err)
// 				return
// 			}

// 			signer := externalSigner{certParsed.PublicKey, test.cfg}

// 			var rand io.Reader
// 			var digest []byte

// 			signerOptsString := "{\"SaltLength\":-1,\"Hash\":5}"
// 			var pSSOptions rsa.PSSOptions
// 			err = json.Unmarshal([]byte(signerOptsString), &pSSOptions)
// 			if err != nil {
// 				t.Fatalf("Unmarshal error: %s\n", err)
// 				return
// 			}

// 			rand = nil
// 			digest = []byte("Zd0PQ68EirC6Ebw43KBjqpCcv/yPyMT1eUOQZDkEuug=")

// 			execCommand = func(command string, args ...string) *exec.Cmd {
// 				csSign := []string{"-test.run=TestHelperProcessSignatureVerificationSign", test.responseSign, "--", command}
// 				csSign = append(csSign, args...)
// 				cmdSign := exec.Command(os.Args[0], csSign...)
// 				return cmdSign
// 			}
// 			// helperResponse = &test.responseSign
// 			// fmt.Fprintf(os.Stderr, "TEST: response: %v\n", helperResponse)

// 			signatureExt, err := signer.Sign(rand, digest, &pSSOptions)
// 			if err != nil {
// 				fmt.Printf("Error: %s\n", err)
// 				if !test.wantSignErr {
// 					t.Fatal(err)
// 				}
// 				return
// 			}

// 			if test.wantSignErr {
// 				t.Fatal("expected signer error")
// 			}

// 			err = rsa.VerifyPSS(certParsed.PublicKey.(*rsa.PublicKey), newhash, hashed, signatureExt, &opts)
// 			if err != nil {
// 				fmt.Printf("Error: %s\n", err)
// 				if !test.wantVerifErr {
// 					t.Fatal(err)
// 				}
// 				return
// 			}

// 			if test.wantVerifErr {
// 				t.Fatal("expected verification error")
// 			}

// 			// fmt.Fprintf(os.Stderr, "Successfully verified message with signature and public key")
// 		})
// 	}
// }

// func TestTLSCredentialsCA(t *testing.T) {
// 	// now := time.Now()

// 	certPool := x509.NewCertPool()
// 	// // cert, key := genClientCert(t)

// 	// cliPriv, err := rsa.GenerateKey(rand.Reader, 2048)
// 	cliPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	servPriv, err := rsa.GenerateKey(rand.Reader, 2048)

// 	servTmpl := &x509.Certificate{
// 		Subject:      pkix.Name{CommonName: "my-server"},
// 		SerialNumber: big.NewInt(2019),
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().Add(time.Hour),
// 		// DNSNames:     []string{"localhost"},
// 		// DNSNames:    []string{"127.0.0.1"},
// 		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
// 		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 	}

// 	// message := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")

// 	// opts := rsa.PSSOptions{
// 	// 	SaltLength: -1,
// 	// 	Hash:       crypto.SHA256.HashFunc(),
// 	// }

// 	// PSSmessage := message
// 	// newhash := crypto.SHA256
// 	// pssh := newhash.New()
// 	// pssh.Write(PSSmessage)
// 	// hashed := pssh.Sum(nil)

// 	// signature, err := rsa.SignPSS(rand.Reader, privKey, newhash, hashed, &opts)

// 	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
// 	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

// 	cliTmpl := &x509.Certificate{
// 		SerialNumber: serialNumber,
// 		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().Add(24 * time.Hour),

// 		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
// 		BasicConstraintsValid: true,
// 	}

// 	caTmpl := &x509.Certificate{
// 		SerialNumber: big.NewInt(2019),
// 		Subject:      pkix.Name{CommonName: "my-ca"},
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().AddDate(10, 0, 0),
// 		IsCA:         true,
// 		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
// 		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
// 		BasicConstraintsValid: true,
// 	}

// 	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPrivKey.Public(), caPrivKey)
// 	caCertPEM := pem.EncodeToMemory(&pem.Block{Bytes: caCertDER, Type: "CERTIFICATE"})

// 	// caPrivDER, err := x509.MarshalECPrivateKey(caPriv)
// 	// caPrivPEM := pem.EncodeToMemory(&pem.Block{Bytes: caPrivDER, Type: "EC PRIVATE KEY"})

// 	caCert, err := x509.ParseCertificate(caCertDER)

// 	cliCert, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, cliPriv.Public(), caPrivKey)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	cliCertPEM := pem.EncodeToMemory(&pem.Block{
// 		Type: "CERTIFICATE", Bytes: cliCert,
// 	})

// 	// cliPrivDER := x509.MarshalPKCS1PrivateKey(cliPriv)
// 	cliPrivDER, _ := x509.MarshalECPrivateKey(cliPriv)
// 	cliPrivPEM := pem.EncodeToMemory(&pem.Block{
// 		Type: "RSA PRIVATE KEY", Bytes: cliPrivDER,
// 	})
// 	clientTLSCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliCert}), cliPrivPEM)

// 	servCertDER, err := x509.CreateCertificate(rand.Reader, servTmpl, caCert, servPriv.Public(), caPrivKey)
// 	servPrivDER := x509.MarshalPKCS1PrivateKey(servPriv)
// 	servCertPEM := pem.EncodeToMemory(&pem.Block{
// 		Type: "CERTIFICATE", Bytes: servCertDER,
// 	})
// 	servPrivPEM := pem.EncodeToMemory(&pem.Block{
// 		Type: "RSA PRIVATE KEY", Bytes: servPrivDER,
// 	})
// 	servTLSCert, err := tls.X509KeyPair(servCertPEM, servPrivPEM)

// 	certPool.AppendCertsFromPEM(caCertPEM)
// 	certPool.AppendCertsFromPEM(cliCertPEM)

// 	// certPool.AppendCertsFromPEM(caCertPEM)
// 	// certPool.AppendCertsFromPEM()
// 	// certPool.AppendCertsFromPEM(caCertPEM)

// 	// if !certPool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliCert})) {
// 	// 	t.Fatal("failed to add client cert to CertPool")
// 	// }

// 	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Printf("INSIDE SERVER!\n")

// 		fmt.Printf("request TLS.CipherSuite: %v\n", r.TLS.CipherSuite)
// 		fmt.Printf("request TLS.DidResume: %v\n", r.TLS.DidResume)
// 		fmt.Printf("request TLS.CipherSuite: %v\n", r.TLS.VerifiedChains)
// 		fmt.Printf("request header: %v\n", r.Header)
// 		body, err := ioutil.ReadAll(r.Body)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		bodyString := string(body)
// 		fmt.Printf("requestbody: %s\n", bodyString)
// 		fmt.Fprintln(w, "ok")
// 	}))
// 	server.TLS = &tls.Config{
// 		Certificates: []tls.Certificate{servTLSCert},
// 		ClientAuth:   tls.RequireAndVerifyClientCert,
// 		// ClientAuth: tls.RequireAnyClientCert,
// 		// ClientAuth: tls.RequestClientCert,
// 		// ClientAuth: tls.NoClientCert,
// 		ClientCAs: certPool,
// 	}
// 	server.StartTLS()
// 	defer server.Close()

// 	authedClient := &http.Client{
// 		Transport: &http.Transport{
// 			TLSClientConfig: &tls.Config{
// 				// InsecureSkipVerify: true,
// 				RootCAs:      certPool,
// 				Certificates: []tls.Certificate{clientTLSCert},
// 			},
// 		},
// 	}

// 	_, err = authedClient.Get(server.URL)

// 	if err != nil {
// 		fmt.Printf("AuthedClient Error: %s\n", err)
// 	} else {
// 		fmt.Printf("AuthedClient SUCCESS!\n")
// 	}

// 	// a, err := newAuthenticator(newCache(), &api.ExecConfig{
// 	// 	Command:    "./testdata/test-plugin.sh",
// 	// 	APIVersion: "client.authentication.k8s.io/v1alpha1",
// 	// })
// 	var clusterAddress string
// 	var persister restclient.AuthProviderConfigPersister
// 	cfg := map[string]string{
// 		"pathExec":  "/path/to/externalSigner",
// 		"pathLib":   "/path/to/library.so",
// 		"slot-id":   "0",
// 		"object-id": "2",
// 	}

// 	responseGetCertificate := "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"" + b64.StdEncoding.EncodeToString(cliCert) + "\"}"

// 	execCommand = func(command string, args ...string) *exec.Cmd {
// 		cs := []string{"-test.run=TestHelperProcessSignatureVerificationGetCertificate", responseGetCertificate, "--", command}
// 		// cs := []string{"-test.run=TestHelperProcessSignatureVerification", test.responseGetCertificate, test.responseSign, "--", command}
// 		cs = append(cs, args...)
// 		cmd := exec.Command(os.Args[0], cs...)
// 		return cmd
// 	}

// 	provider, err := newExternalSignerAuthProvider(clusterAddress, cfg, persister)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	var a *Authenticator
// 	a = provider.(*Authenticator)

// 	if err != nil {
// 		t.Fatal(err)
// 	}
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

// 	fmt.Printf("caCertPEM: \n%s\n", string(caCertPEM))
// 	fmt.Printf("cliCertPEM: \n%s\n", string(cliCertPEM))

// 	// We're not interested in server's cert, this test is about client cert.
// 	// tc := &transport.Config{}
// 	tc := &transport.Config{TLS: transport.TLSConfig{Insecure: true}}

// 	// tc := &transport.Config{TLS: transport.TLSConfig{CAData: caCertPEM}}
// 	// tc := &transport.Config{TLS: transport.TLSConfig{}}

// 	// tc := &transport.Config{TLS: transport.TLSConfig{CertData: cliCertPEM, Insecure: true}}

// 	// tc := &transport.Config{TLS: transport.TLSConfig{CertData: cliCertPEM, CAData: caCertPEM}}

// 	if err := a.UpdateTransportConfig(tc); err != nil {
// 		t.Fatal(err)
// 	}

// 	// certDataJSON, err := json.Marshal(clientTLSCert)
// 	// if err != nil {
// 	// 	fmt.Printf("Error: %s\n", err)
// 	// }
// 	// fmt.Printf("clientTLSCert: %s\n", string(certDataJSON))

// 	get := func(t *testing.T, desc string, wantErr bool) {
// 		t.Run(desc, func(t *testing.T) {
// 			// tlsCfg, err := transport.TLSConfigFor(tc)
// 			if err != nil {
// 				t.Fatal("TLSConfigFor:", err)
// 			}
// 			client := http.Client{
// 				// Transport: &http.Transport{TLSClientConfig: tlsCfg},
// 				Transport: &http.Transport{
// 					TLSClientConfig: &tls.Config{
// 						// InsecureSkipVerify: true,
// 						RootCAs: certPool,

// 						Certificates: []tls.Certificate{clientTLSCert},
// 					},
// 				},
// 			}

// 			// tlsCertsClient, err := json.Marshal(client.Transport)
// 			// if err != nil {
// 			// 	fmt.Printf("Error: %s\n", err)
// 			// }
// 			// fmt.Printf("client: %s\n", string(tlsCertsClient))

// 			fmt.Printf("server.URL: %s\n", server.URL)
// 			// fmt.Printf("server.URL: %s\n", client.)

// 			resp, err := client.Get(server.URL)

// 			body, err := ioutil.ReadAll(resp.Body)
// 			bodyString := string(body)
// 			fmt.Printf("response body: %s\n", bodyString)

// 			// resp, err := client.Get("localhost:8443")
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

// 	// keyRaw := x509.MarshalPKCS1PrivateKey(privKey)
// 	// keyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyRaw})

// 	// output = &clientauthentication.ExecCredential{
// 	// 	Status: &clientauthentication.ExecCredentialStatus{
// 	// 		ClientCertificateData: string(certBytes),
// 	// 		ClientKeyData:         string(keyPem),
// 	// 		ExpirationTimestamp:   &v1.Time{now.Add(time.Hour)},
// 	// 	},
// 	// }
// 	get(t, "valid TLS cert", false)

// 	// Advance time to force re-exec.
// 	// nCert, nKey := genClientCert(t)
// 	// now = now.Add(time.Hour * 2)
// 	// output = &clientauthentication.ExecCredential{
// 	// 	Status: &clientauthentication.ExecCredentialStatus{
// 	// 		ClientCertificateData: string(nCert),
// 	// 		ClientKeyData:         string(nKey),
// 	// 		ExpirationTimestamp:   &v1.Time{now.Add(time.Hour)},
// 	// 	},
// 	// }
// 	// get(t, "untrusted TLS cert", true)

// 	// now = now.Add(time.Hour * 2)
// 	// output = &clientauthentication.ExecCredential{
// 	// 	Status: &clientauthentication.ExecCredentialStatus{
// 	// 		ClientCertificateData: string(cert),
// 	// 		ClientKeyData:         string(key),
// 	// 		ExpirationTimestamp:   &v1.Time{now.Add(time.Hour)},
// 	// 	},
// 	// }
// 	// get(t, "valid TLS cert again", false)
// }

// func TestHelperProcessSignatureVerificationSignWithDigest(t *testing.T) {
// 	// fmt.Fprintf(os.Stderr, "HELPER: TestHelperProcessSignatureVerificationSignWithDigest, args: %d\n", len(os.Args))
// 	if len(os.Args) < 5 {
// 		t.Skip()
// 	}

// 	key, err := b64.StdEncoding.DecodeString(os.Args[2])
// 	if err != nil {
// 		t.Fatalf("Key decode error: %s\n", err)
// 		return
// 	}

// 	privKey, err := x509.ParsePKCS1PrivateKey(key)
// 	if err != nil {
// 		t.Fatalf("Key parsing error: %s\n", err)
// 		return
// 	}

// 	signRequest := os.Getenv("EXTERNAL_SIGNER_PLUGIN_CONFIG")
// 	// fmt.Fprintf(os.Stderr, "Args: %s\n", signRequest)

// 	type SignMessage struct {
// 		APIVersion     string            `json:"apiVersion"`
// 		Kind           string            `json:"kind"`
// 		Configuration  map[string]string `json:"configuration"`
// 		Digest         string            `json:"digest"`
// 		SignerOptsType string            `json:"signerOptsType"`
// 		SignerOpts     string            `json:"signerOpts"`
// 	}

// 	var signMessage SignMessage

// 	err = json.Unmarshal([]byte(signRequest), &signMessage)
// 	if err != nil {
// 		t.Fatalf("Unmarshal error: %s\n", err)
// 		return
// 	}

// 	// fmt.Fprintf(os.Stderr, "signMessage.Digest: %s\n", signMessage.Digest)
// 	digest, err := b64.StdEncoding.DecodeString(signMessage.Digest)

// 	if signMessage.Configuration["pathLib"] == "" {
// 		t.Fatal(err)
// 		return
// 	}

// 	signerOptsString := "{\"SaltLength\":-1,\"Hash\":5}"
// 	var pSSOptions rsa.PSSOptions
// 	err = json.Unmarshal([]byte(signerOptsString), &pSSOptions)
// 	if err != nil {
// 		t.Fatalf("Unmarshal error: %s\n", err)
// 		return
// 	}

// 	newhash := crypto.SHA256

// 	opts := rsa.PSSOptions{
// 		SaltLength: -1,
// 		Hash:       crypto.SHA256.HashFunc(),
// 	}

// 	signature, err := rsa.SignPSS(rand.Reader, privKey, newhash, digest, &opts)

// 	response := "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"" + b64.StdEncoding.EncodeToString(signature) + "\"}"

// 	fmt.Fprintf(os.Stdout, response)
// 	os.Exit(0)
// }

// func TestTLSCredentialsSelfSigned(t *testing.T) {
// 	certPool := x509.NewCertPool()
// 	certRaw, privKey, cert := genClientCert(t)
// 	_, nKey, _ := genClientCert(t)
// 	// nCertRaw, nKey, nCert := genClientCert(t)

// 	if !certPool.AppendCertsFromPEM(cert) {
// 		t.Fatal("failed to add client cert to CertPool")
// 	}
// 	// if !certPool.AppendCertsFromPEM(nCert) {
// 	// 	t.Fatal("failed to add client nCert to CertPool")
// 	// }

// 	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// fmt.Printf("INSIDE SERVER!\n")

// 		// fmt.Printf("request TLS.CipherSuite: %v\n", r.TLS.CipherSuite)
// 		// fmt.Printf("request TLS.DidResume: %v\n", r.TLS.DidResume)
// 		// fmt.Printf("request TLS.CipherSuite: %v\n", r.TLS.VerifiedChains)
// 		// fmt.Printf("request header: %v\n", r.Header)
// 		// body, err := ioutil.ReadAll(r.Body)
// 		// if err != nil {
// 		// 	t.Fatal(err)
// 		// }
// 		// bodyString := string(body)
// 		// fmt.Printf("requestbody: %s\n", bodyString)
// 		fmt.Fprintln(w, "ok")
// 	}))
// 	server.TLS = &tls.Config{
// 		ClientAuth: tls.RequireAndVerifyClientCert,
// 		ClientCAs:  certPool,
// 	}
// 	server.StartTLS()
// 	defer server.Close()

// 	var clusterAddress string
// 	var persister restclient.AuthProviderConfigPersister
// 	cfg := map[string]string{
// 		"pathExec":  "/path/to/externalSigner",
// 		"pathLib":   "/path/to/library.so",
// 		"slot-id":   "0",
// 		"object-id": "2",
// 	}

// 	responseGetCertificate := "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"" + b64.StdEncoding.EncodeToString(certRaw) + "\"}"

// 	// fmt.Printf("responseGetCertificate: %s\n", responseGetCertificate)

// 	execCommand = func(command string, args ...string) *exec.Cmd {
// 		cs := []string{"-test.run=TestHelperProcessSignatureVerificationGetCertificate", responseGetCertificate, "--", command}
// 		cs = append(cs, args...)
// 		cmd := exec.Command(os.Args[0], cs...)
// 		return cmd
// 	}

// 	provider, err := newExternalSignerAuthProvider(clusterAddress, cfg, persister)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	var a *Authenticator
// 	a = provider.(*Authenticator)

// 	tc := &transport.Config{TLS: transport.TLSConfig{Insecure: true}}
// 	if err := a.UpdateTransportConfig(tc); err != nil {
// 		t.Fatal(err)
// 	}

// 	execCommand = func(command string, args ...string) *exec.Cmd {
// 		csSign := []string{"-test.run=TestHelperProcessSignatureVerificationSignWithDigest", b64.StdEncoding.EncodeToString(privKey), "--", command}
// 		csSign = append(csSign, args...)
// 		cmdSign := exec.Command(os.Args[0], csSign...)
// 		return cmdSign
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

// 	get(t, "valid TLS cert", false)

// 	execCommand = func(command string, args ...string) *exec.Cmd {
// 		csSign := []string{"-test.run=TestHelperProcessSignatureVerificationSignWithDigest", b64.StdEncoding.EncodeToString(nKey), "--", command}
// 		csSign = append(csSign, args...)
// 		cmdSign := exec.Command(os.Args[0], csSign...)
// 		return cmdSign
// 	}

// 	get(t, "untrusted TLS cert", true)

// 	// nResponseGetCertificate := "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalPublicKey\",\"certificate\":\"" + b64.StdEncoding.EncodeToString(nCertRaw) + "\"}"

// 	// execCommand = func(command string, args ...string) *exec.Cmd {
// 	// 	cs := []string{"-test.run=TestHelperProcessSignatureVerificationGetCertificate", nResponseGetCertificate, "--", command}
// 	// 	cs = append(cs, args...)
// 	// 	cmd := exec.Command(os.Args[0], cs...)
// 	// 	return cmd
// 	// }

// 	// nprovider, err := newExternalSignerAuthProvider(clusterAddress, cfg, persister)
// 	// if err != nil {
// 	// 	t.Fatal(err)
// 	// }
// 	// var na *Authenticator
// 	// na = nprovider.(*Authenticator)

// 	// ntc := &transport.Config{TLS: transport.TLSConfig{Insecure: true}}
// 	// if err := na.UpdateTransportConfig(ntc); err != nil {
// 	// 	t.Fatal(err)
// 	// }

// 	// nGet := func(t *testing.T, desc string, wantErr bool) {
// 	// 	t.Run(desc, func(t *testing.T) {
// 	// 		tlsCfg, err := transport.TLSConfigFor(ntc)
// 	// 		if err != nil {
// 	// 			t.Fatal("TLSConfigFor:", err)
// 	// 		}
// 	// 		client := http.Client{
// 	// 			Transport: &http.Transport{TLSClientConfig: tlsCfg},
// 	// 		}

// 	// 		resp, err := client.Get(server.URL)

// 	// 		switch {
// 	// 		case err != nil && !wantErr:
// 	// 			t.Errorf("got client.Get error: %q, want nil", err)
// 	// 		case err == nil && wantErr:
// 	// 			t.Error("got nil client.Get error, want non-nil")
// 	// 		}
// 	// 		if err == nil {
// 	// 			resp.Body.Close()
// 	// 		}

// 	// 	})
// 	// }

// 	// nGet(t, "invalid signature", false)
// }

// // genClientCert generates an x509 certificate for testing. Certificate and key
// // are returned in PEM encoding. The generated cert expires in 24 hours.
// func genClientCert(t *testing.T) ([]byte, []byte, []byte) {
// 	key, err := rsa.GenerateKey(rand.Reader, 2048)
// 	// key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	keyRaw := x509.MarshalPKCS1PrivateKey(key)
// 	// keyRaw, err := x509.MarshalECPrivateKey(key)
// 	// if err != nil {
// 	// t.Fatal(err)
// 	// }
// 	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
// 	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	cert := &x509.Certificate{
// 		SerialNumber: serialNumber,
// 		Subject:      pkix.Name{Organization: []string{"Acme Co"}},
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().Add(24 * time.Hour),

// 		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
// 		BasicConstraintsValid: true,
// 	}
// 	certRaw, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	// fmt.Printf("cert: %v\n", cert)

// 	return certRaw,
// 		keyRaw,
// 		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw})
// }
