package testing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"k8s.io/client-go/plugin/pkg/client/auth/externalsigner/v1alpha1"
	"k8s.io/klog"
)

const (
	// Now only supported unix domain socket.
	unixProtocol = "unix"

	// Current version for the protocol interface definition.
	kmsapiVersion = "v1beta1"
)

// ExternalSignerPlugin gRPC sever for a mock KMS provider.
// Uses base64 to simulate encrypt and decrypt.
type ExternalSignerPlugin struct {
	grpcServer *grpc.Server
	listener   net.Listener
	mu         *sync.Mutex
	// lastEncryptRequest *kmsapi.EncryptRequest
	inFailedState       bool
	ver                 string
	socketPath          string
	certificateResponse v1alpha1.CertificateResponse
	signatureResponse   v1alpha1.SignatureResponse
	privKeyRaw          []byte
}

// NewExternalSignerPlugin is a constructor for ExternalSignerPlugin.
func NewExternalSignerPlugin(socketPath string, certificateResponse v1alpha1.CertificateResponse, signatureResponse v1alpha1.SignatureResponse, privKey []byte) (*ExternalSignerPlugin, error) {
	server := grpc.NewServer()
	result := &ExternalSignerPlugin{
		grpcServer:          server,
		mu:                  &sync.Mutex{},
		ver:                 kmsapiVersion,
		socketPath:          socketPath,
		certificateResponse: certificateResponse,
		signatureResponse:   signatureResponse,
		privKeyRaw:          privKey,
	}

	v1alpha1.RegisterExternalSignerServiceServer(server, result)
	return result, nil
}

func (p *ExternalSignerPlugin) Version(ctx context.Context, in *v1alpha1.VersionRequest) (*v1alpha1.VersionResponse, error) {
	return nil, nil
}

func (p *ExternalSignerPlugin) GetCertificate(in *v1alpha1.CertificateRequest, stream v1alpha1.ExternalSignerService_GetCertificateServer) error {
	stream.Send(&p.certificateResponse)
	return nil
}

func (p *ExternalSignerPlugin) Sign(in *v1alpha1.SignatureRequest, stream v1alpha1.ExternalSignerService_SignServer) error {
	configMap := in.GetConfiguration()

	path := configMap["pathLib"]
	if path == "" {
		return fmt.Errorf("must provide pathLib")
	}

	_, err := strconv.Atoi(configMap["slotId"])
	if err != nil {
		return fmt.Errorf("must provide integer SlotID: %v", err)
	}

	_, err = strconv.Atoi(configMap["objectId"])
	if err != nil {
		return fmt.Errorf("must provide integer ObjectID: %v", err)
	}

	if p.privKeyRaw == nil {
		fmt.Printf("Key is nil, using prepared response.\n")
		// if &p.signatureResponse != nil {
		stream.Send(&p.signatureResponse)
	} else {
		fmt.Printf("Key is not nil, processing the response.\n")
		privKey, err := x509.ParsePKCS1PrivateKey(p.privKeyRaw)
		if err != nil {
			return fmt.Errorf("Key parsing error: %s\n", err)
		}
		if privKey == nil {
			return fmt.Errorf("private key not found\n")
		}

		digest := in.GetDigest()

		var signature []byte

		switch in.GetSignerType() {
		case v1alpha1.SignatureRequest_RSAPSS:
			pSSOptions := rsa.PSSOptions{
				SaltLength: int(in.GetSignerOptsRSAPSS().GetSaltLenght()),
				Hash:       crypto.Hash(in.GetSignerOptsRSAPSS().GetHash()),
			}

			newhash := crypto.SHA256

			signature, err = rsa.SignPSS(rand.Reader, privKey, newhash, digest, &pSSOptions)

			if err != nil {
				return fmt.Errorf("sign error: %v", err)
			}
		default:
			return fmt.Errorf("SignerOpts for %s are not implemented", in.GetSignerType())
		}
		stream.Send(&v1alpha1.SignatureResponse{Content: &v1alpha1.SignatureResponse_Signature{Signature: signature}})
	}

	return nil
}

// // WaitForExternalSignerPluginToBeUp waits until the plugin is ready to serve requests.
// func WaitForExternalSignerPluginToBeUp(plugin *ExternalSignerPlugin) error {
// 	var gRPCErr error
// 	pollErr := wait.PollImmediate(1*time.Second, wait.ForeverTestTimeout, func() (bool, error) {
// 		_, gRPCErr = plugin.Encrypt(context.Background(), &kmsapi.EncryptRequest{Plain: []byte("foo")})
// 		return gRPCErr == nil, nil
// 	})

// 	if pollErr == wait.ErrWaitTimeout {
// 		return fmt.Errorf("failed to start kms-plugin, error: %v", gRPCErr)
// 	}

// 	return nil
// }

// // LastEncryptRequest returns the last EncryptRequest.Plain sent to the plugin.
// func (s *ExternalSignerPlugin) LastEncryptRequest() []byte {
// 	return s.lastEncryptRequest.Plain
// }

// // SetVersion sets the version of kms-plugin.
// func (s *ExternalSignerPlugin) SetVersion(ver string) {
// 	s.ver = ver
// }

// Start starts plugin's gRPC service.
func (s *ExternalSignerPlugin) Start() error {
	var err error
	s.listener, err = net.Listen(unixProtocol, s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on the unix socket, error: %v", err)
	}
	klog.Infof("Listening on %s", s.socketPath)

	go s.grpcServer.Serve(s.listener)
	return nil
}

// CleanUp stops gRPC server and the underlying listener.
func (s *ExternalSignerPlugin) CleanUp() {
	s.grpcServer.Stop()
	s.listener.Close()
	if !strings.HasPrefix(s.socketPath, "@") || runtime.GOOS != "linux" {
		os.Remove(s.socketPath)
	}
}

// // EnterFailedState places the plugin into failed state.
// func (s *ExternalSignerPlugin) EnterFailedState() {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	s.inFailedState = true
// }

// // ExitFailedState removes the plugin from the failed state.
// func (s *ExternalSignerPlugin) ExitFailedState() {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	s.inFailedState = false
// }

// // Version returns the version of the kms-plugin.
// func (s *ExternalSignerPlugin) Version(ctx context.Context, request *kmsapi.VersionRequest) (*kmsapi.VersionResponse, error) {
// 	klog.Infof("Received request for Version: %v", request)
// 	return &kmsapi.VersionResponse{Version: s.ver, RuntimeName: "testKMS", RuntimeVersion: "0.0.1"}, nil
// }

// // Decrypt performs base64 decoding of the payload of kms.DecryptRequest.
// func (s *ExternalSignerPlugin) Decrypt(ctx context.Context, request *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
// 	klog.V(3).Infof("Received Decrypt Request for DEK: %s", string(request.Cipher))

// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	if s.inFailedState {
// 		return nil, status.Error(codes.FailedPrecondition, "failed precondition - key disabled")
// 	}

// 	buf := make([]byte, base64.StdEncoding.DecodedLen(len(request.Cipher)))
// 	n, err := base64.StdEncoding.Decode(buf, request.Cipher)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &kmsapi.DecryptResponse{Plain: buf[:n]}, nil
// }

// // Encrypt performs base64 encoding of the payload of kms.EncryptRequest.
// func (s *ExternalSignerPlugin) Encrypt(ctx context.Context, request *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
// 	klog.V(3).Infof("Received Encrypt Request for DEK: %x", request.Plain)
// 	s.mu.Lock()
// 	defer s.mu.Unlock()
// 	s.lastEncryptRequest = request

// 	if s.inFailedState {
// 		return nil, status.Error(codes.FailedPrecondition, "failed precondition - key disabled")
// 	}

// 	buf := make([]byte, base64.StdEncoding.EncodedLen(len(request.Plain)))
// 	base64.StdEncoding.Encode(buf, request.Plain)

// 	return &kmsapi.EncryptResponse{Cipher: buf}, nil
// }
