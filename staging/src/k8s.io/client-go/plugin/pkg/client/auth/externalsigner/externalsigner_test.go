package externalsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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
	validCert *tls.Certificate
	x509Cert  *x509.Certificate
)

// var (
// 	certData, _ = b64.StdEncoding.DecodeString("-----BEGIN CERTIFICATE-----MIIC6zCCAdOgAwIBAgIQPp3pFNWcKrNGBSVdx/zMUDANBgkqhkiG9w0BAQsFADAQMQ4wDAYDVQQKEwVqYWt1YjAeFw0xOTA5MTExMjQ0MDBaFw0yMjA4MjYxMjQ0MDBaMBwxGjAYBgNVBAoMEWpha3ViLjxib290c3RyYXA+MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuw1gaKFz6UVPEA5XJuCgU4+FWZgOx70Zq3+NKr3yEGVJ2s8Wu7WV8YpDTkekjg9Y9+k6NEHoNvDlubuAzqgbJhHnQlD+hLmMsz+uALCdclNdiBzQjr9P7HB4YpGgTueTaoDOMCECGwt69yyBrgo5lawgF/4dRNmsxtfVcCYIAPuc3bUaXO4pC/C/eMTW1Ck5cFUYYZgY23pPKh7sWGfMi0srArGInp7JSAFfAqh3DuEx0kwKF+DqTFUZLg+Z+t+Q+lDj1Uk/1TZlLuKpfkspP97qbiRWcAIe6CV0wASy+zi+xEjbxVt+tuuYfaGdBaeCsIkIoJQGf7MzzLmj8ibj4QIDAQABozUwMzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAf77eh/hws9/ZrgWgRMIP2oYHQhZk9LJD/ewVq6emtSPPbSKxmC4EntoAwlpWWXn/rFlE/CcAJEphRNYhqVL8187ltO6nq/sA4BrDR87x1CUgcy8tenWbVHKE6CAOL+vUUHwY7axRnup4FSl407u9ViAEmB1l3IoDY2G9Ie4NkDn6uBBgmwdpQOr7WnT9G0gxcrcXRKYHMj8aYWcwqQ6RATgsI/y3u+nXfbMhsRAecWvklyv0WYFX94A5GieiqGEXVQ3BzEux+vcdBjmUsDP3qfVg/+d9p5mIIaHWI579ZPx+4U/KF1jgyAXIFhVAr2AkxhlwJBM+/rBsZvUH8dfG+Q==-----END CERTIFICATE-----")
// 	keyData, _  = b64.StdEncoding.DecodeString("-----BEGIN RSA PRIVATE KEY-----MIIEpQIBAAKCAQEAuw1gaKFz6UVPEA5XJuCgU4+FWZgOx70Zq3+NKr3yEGVJ2s8Wu7WV8YpDTkekjg9Y9+k6NEHoNvDlubuAzqgbJhHnQlD+hLmMsz+uALCdclNdiBzQjr9P7HB4YpGgTueTaoDOMCECGwt69yyBrgo5lawgF/4dRNmsxtfVcCYIAPuc3bUaXO4pC/C/eMTW1Ck5cFUYYZgY23pPKh7sWGfMi0srArGInp7JSAFfAqh3DuEx0kwKF+DqTFUZLg+Z+t+Q+lDj1Uk/1TZlLuKpfkspP97qbiRWcAIe6CV0wASy+zi+xEjbxVt+tuuYfaGdBaeCsIkIoJQGf7MzzLmj8ibj4QIDAQABAoIBACFHg/uZnhHGrwZgRsk39c5oHoWONDL9Re/pRahxGvwnyTgQ2C6VZBQRUWBABtrviBizehOKFlKQEY81+PjLl+jyDn8SAfaDPLE3hzHAOoL4qg9pcQG0r/eVGxYOasMfGG8+c3DErqc5J6uKU5gvYYdrlFowb+yr/b1y8Rp+6bWiwGJxdQBfMCWuNQS3npjFppT7G7fGRtSVasd03e/dKE315sNwT2RlM7svdPGGC2Oa77alG3WsnzkITCrQUsmBSr3tJ7pVNxT1luVr3VE1NX4jPARC6zhB87mjMFqIOGQsjFhhwi2tWIuJzSqYdCYtxfDL341p6+QAazroBKSmFzECgYEAyMtCgjN6/XIBJ50/szjKG4BOmIKeUySskTYt/JJwwkEOcWqqTqrq+Ygu9CmoWbo5ARimd1+Tf7+cCQnUYva4FOiw1tbQcDA23gXG7u3fCQC5/BMtf1DmN2iLKvFTSJ1F2YSzk+sZ8GtS6zr6tIG/3ObFcmGDHRS6jtQi/Y99XO8CgYEA7nrqODh2lX6/UeMlhDO8ksU4GnYpI4hXMmKaqkpVAXB6n5G5tJ+OZZCBAQBHZ9rim05PjK/ep0ky2GTx78C0m8okAqRvHqLgLcenThS2zYh1l4LFUgCFd1v4kKRDORck2sb1NqbkEJpon3ax02FZSUFsz73ColP0iJ6We/PybC8CgYEAtFx/3VxIuafSCbdiJKZ6RMG3155cgOqMZ9N280zHJHYzdwUM/aThdEszgfZ5Vj/EPIvb25Zqc3G1wxilQk/DgmSRlClZCa0FW+Fsk+nvUbLpXNgNIjOU12h8uZIT8UH0IDLm65NetWpyDQHpeIKjyNUxvlCA6XpZKTq8Q27EeNkCgYEA6yAG441P5Y8ExJDGwXRc/Pwzl2tenijjh8rOIQ2OiA/E5qS/ysTxmVOCzWDgBhY6C9OG/Pe894Rk/BNyseZ2a48+N9i1sif2DUzmuEYWAckD33DQaUwYSxlDliBOIvCdppI43DxpabFDa82UAAvgAyjdRmkah/9sfnKVffqDzoMCgYEAsF5+iagZltunlYwg2BQ0tDn1aveLfpJuzy4chygGfADGH4GLkq88sjeTLkrNRl8VrHZ+vENqSL7r4Oye4rK59W63mnjBE/Xeh7b6IXvmus624cpgyiz0VSpKCj098cuJgp/2S95QUVxqZ/6vULFAfZqJe47kHaVYD8qub5N4AIg=-----END RSA PRIVATE KEY-----")
// 	// validCert   *tls.Certificate
// 	cert *x509.Certificate
// 	key  *rsa.PrivateKey
// )

// func init() {
// 	// certExt, err := b64.StdEncoding.DecodeString("MIIC6zCCAdOgAwIBAgIQPp3pFNWcKrNGBSVdx/zMUDANBgkqhkiG9w0BAQsFADAQ\nMQ4wDAYDVQQKEwVqYWt1YjAeFw0xOTA5MTExMjQ0MDBaFw0yMjA4MjYxMjQ0MDBa\nMBwxGjAYBgNVBAoMEWpha3ViLjxib290c3RyYXA+MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAuw1gaKFz6UVPEA5XJuCgU4+FWZgOx70Zq3+NKr3yEGVJ\n2s8Wu7WV8YpDTkekjg9Y9+k6NEHoNvDlubuAzqgbJhHnQlD+hLmMsz+uALCdclNd\niBzQjr9P7HB4YpGgTueTaoDOMCECGwt69yyBrgo5lawgF/4dRNmsxtfVcCYIAPuc\n3bUaXO4pC/C/eMTW1Ck5cFUYYZgY23pPKh7sWGfMi0srArGInp7JSAFfAqh3DuEx\n0kwKF+DqTFUZLg+Z+t+Q+lDj1Uk/1TZlLuKpfkspP97qbiRWcAIe6CV0wASy+zi+\nxEjbxVt+tuuYfaGdBaeCsIkIoJQGf7MzzLmj8ibj4QIDAQABozUwMzAOBgNVHQ8B\nAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkq\nhkiG9w0BAQsFAAOCAQEAf77eh/hws9/ZrgWgRMIP2oYHQhZk9LJD/ewVq6emtSPP\nbSKxmC4EntoAwlpWWXn/rFlE/CcAJEphRNYhqVL8187ltO6nq/sA4BrDR87x1CUg\ncy8tenWbVHKE6CAOL+vUUHwY7axRnup4FSl407u9ViAEmB1l3IoDY2G9Ie4NkDn6\nuBBgmwdpQOr7WnT9G0gxcrcXRKYHMj8aYWcwqQ6RATgsI/y3u+nXfbMhsRAecWvk\nlyv0WYFX94A5GieiqGEXVQ3BzEux+vcdBjmUsDP3qfVg/+d9p5mIIaHWI579ZPx+\n4U/KF1jgyAXIFhVAr2AkxhlwJBM+/rBsZvUH8dfG+Q==")
// 	// if err != nil {
// 	// 	fmt.Errorf("decode error: %v", err)
// 	// }

// 	var err error
// 	cert, err = x509.ParseCertificate([]byte(certData))
// 	if err != nil {
// 		fmt.Errorf("parse certificate error: %v", err)
// 	}

// 	key, err = rsa.DecryptPKCS1v15 ([]byte(keyData))
// 	// validCert := &tls.Certificate{
// 	// 	Certificate: [][]byte{certExt},
// 	// 	PrivateKey:  nil,
// 	// 	// PrivateKey: &externalSigner{cert.PublicKey, cfg, protocol},
// 	// }
// }

func init() {
	// var err error
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		panic(err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}
	validCert = &cert
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

// func fakeExecCommandSign(command string, args ...string) *exec.Cmd {
// 	cs := []string{"-test.run=TestHelperProcessSign", "--", command}
// 	cs = append(cs, args...)
// 	cmd := exec.Command(os.Args[0], cs...)
// 	return cmd
// }

func TestHelperProcessSign(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 {
		t.Skip()
	}

	response := os.Args[2]
	// signRequest := os.Args[5]
	signRequest := os.Getenv("EXTERNAL_SIGNER_PKCS11_PLUGIN_CONFIG")
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
	// type execCommandType func(command string, args ...string) *exec.Cmd

	tests := []struct {
		name     string
		cfg      map[string]string
		response string
		// execCommand execCommandType
		wantErr bool
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
			// execCommand: func(command string, args ...string) *exec.Cmd {
			// 	response := "{\"apiVersion\":\"external-signer.authentication.k8s.io/v1alpha1\",\"kind\":\"ExternalSigner\",\"signature\":\"w1lLwUeKCsrMERawMpoDfMiFlf7+8OAaPvAI4/9iUZM56qroJv3uCty0HlPixaMV8Si6vszRS1CuZbpRSqbwg6+FC6OKzd7Gkfm8zWGVi7bsMpiD9TBy7L0Gyc5FcXY5IWeXyHBw9HNNlEAOhrL1juhVu2DCEJ9QbLQ+4mHFrdHWJVN8pvvc4hHyRFv50r15fNeDs76PN9oLDrszeVswCPJuiN5IaOxO3nm1G/4EGSYDjLeynNSwuker7h8J58T1f5+OIAfeJDpQRtgCExPW4n9OnZPPL+uj2MyMqbXl5HnvrEuBY8EvqiY2Uc2Nte9uTHqpQHagrFU4bn4nhK+Qug==\"}"
			// 	cs := []string{"-test.run=TestHelperProcessSign", response, "--", command}
			// 	cs = append(cs, args...)
			// 	cmd := exec.Command(os.Args[0], cs...)
			// 	return cmd
			// },
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
			// cfg := map[string]string{
			// 	"pathExec":  "/path/to/externalSigner",
			// 	"pathLib":   "/path/to/library.so",
			// 	"slot-id":   "0",
			// 	"object-id": "2",
			// }
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

			// execCommand = test.execCommand
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

// func fakeExecCommandGetCertificate(command string, args ...string) *exec.Cmd {
// 	cs := []string{"-test.run=TestHelperProcessGetCertificate", "--", command}
// 	cs = append(cs, args...)
// 	cmd := exec.Command(os.Args[0], cs...)
// 	return cmd
// }

func TestHelperProcessGetCertificate(t *testing.T) {
	t.Helper()
	if len(os.Args) < 5 {
		t.Skip()
	}

	response := os.Args[2]
	certificateRequest := os.Getenv("EXTERNAL_SIGNER_PKCS11_PLUGIN_CONFIG")
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
			// cfg := map[string]string{
			// 	"pathExec":  "/path/to/externalSigner",
			// 	"pathLib":   "/path/to/library.so",
			// 	"slot-id":   "0",
			// 	"object-id": "2",
			// }

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
