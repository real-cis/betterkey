package sgx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"slices"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
)

// MasterKeystore
// hasSGX = true, fs on sgx, sealed with productId & signerId
// hasSGX = false, plain fs
type MasterKeyStore struct {
	File             string
	ConfiguredNodeId *common.NodeInfo
	cachedMasterkey  *common.Member
	hasSGX           bool
}

type SGXTlsConfig struct {
	enclaveConfig  *common.EnclaveConfig
	reportVerifier *func(report attestation.Report) error
	certVerifer    *func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	privateKey     *ecdsa.PrivateKey
	certificate    []byte
}

type AutoTlsConfig struct {
	tlsConfig *tls.Config
}

func (a *AutoTlsConfig) ClientTlsConfig() *tls.Config {
	return a.tlsConfig
}

func (a *AutoTlsConfig) ServerTlsConfig() *tls.Config {
	return a.tlsConfig
}

// https://github.com/openenclave/openenclave/blob/master/include/openenclave/internal/report.h
var oidOeNewQuote = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 105, 1}

func newCertTemplate(CN string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: CN},
		DNSNames:     []string{CN},
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	return template, nil
}

// pass nil as enclaveConfig for non-sgx env
func NewNodeTlsConfig(CN string, enclaveConfig *common.EnclaveConfig) (common.NodeTLSConfig, error) {
	template, err := newCertTemplate(CN)
	if err != nil {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, err
	}
	// get report for the public key
	hash, err := crypto.HashPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	if enclaveConfig != nil {
		report, err := enclave.GetRemoteReport(hash[:])
		if err != nil {
			return nil, err
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: oidOeNewQuote, Value: report})
		cert, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			return nil, err
		}
		reportVerifier := func(report attestation.Report) error {
			return VerifyReport(report, enclaveConfig)
		}

		certVerifier := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// parse certificate
			if len(rawCerts) <= 0 {
				return errors.New("rawCerts is empty")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			// verify self-signed certificate
			roots := x509.NewCertPool()
			roots.AddCert(cert)
			_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
			if err != nil {
				return err
			}

			hash, err := crypto.HashPublicKey(cert.PublicKey)
			if err != nil {
				return err
			}

			// verify embedded report
			for _, ex := range cert.Extensions {
				if ex.Id.Equal(oidOeNewQuote) {
					slog.Info("verifying remote certificate", "dnsNames", cert.DNSNames)
					report, err := enclave.VerifyRemoteReport(ex.Value)
					if err != nil {
						return err
					}
					if !bytes.Equal(report.Data[:len(hash)], hash) {
						return errors.New("certificate hash does not match report data")
					}
					return VerifyReport(report, enclaveConfig)
				}
			}
			return errors.New("certificate does not contain attestation report")
		}

		var cfg common.NodeTLSConfig = &SGXTlsConfig{
			enclaveConfig:  enclaveConfig,
			privateKey:     priv,
			certificate:    cert,
			certVerifer:    &certVerifier,
			reportVerifier: &reportVerifier,
		}
		return cfg, nil
	} else {
		cert, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		if err != nil {
			return nil, err
		}
		nopCfg := &tls.Config{
			InsecureSkipVerify: true,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert},
					PrivateKey:  priv,
				},
			}}
		var cfg common.NodeTLSConfig = &AutoTlsConfig{
			tlsConfig: nopCfg,
		}
		return cfg, nil
	}
}

func (n *SGXTlsConfig) ServerTlsConfig() *tls.Config {

	tlsCfg := enclave.CreateAttestationClientTLSConfig(*n.reportVerifier)
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.ClientAuth = tls.RequestClientCert
	tlsCfg.VerifyPeerCertificate = *n.certVerifer
	tlsCfg.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{n.certificate},
			PrivateKey:  n.privateKey,
		},
	}

	return tlsCfg
}

func (n *SGXTlsConfig) ClientTlsConfig() *tls.Config {

	tlsCfg := enclave.CreateAttestationClientTLSConfig(*n.reportVerifier)
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{n.certificate},
			PrivateKey:  n.privateKey,
		},
	}

	return tlsCfg
}

func VerifyReport(report attestation.Report, config *common.EnclaveConfig) error {
	productId := binary.LittleEndian.Uint16(report.ProductID)
	if productId != config.ProductId {
		return fmt.Errorf("productId %v does not match,expect %v", productId, config.ProductId)
	}
	var matchVersion = false
	if slices.Contains(config.SecurityVersions, report.SecurityVersion) {
		matchVersion = true
	}
	if !matchVersion {
		return fmt.Errorf("SecurityVersion %v does not match,expects %v", report.SecurityVersion, config.SecurityVersions)
	}

	if config.Debug != report.Debug {
		return fmt.Errorf("debug=%v does not match,expects %v", report.Debug, config.Debug)
	}

	signerId := make([]string, len(report.SignerID))
	for i, v := range report.SignerID {
		signerId[i] = fmt.Sprintf("%d", v)
	}
	if config.SignerId != strings.Join(signerId, " ") {
		return fmt.Errorf("SignerId %s does not match,expects %v", string(report.SignerID), config.SignerId)
	}

	slog.Info("attestation.Report verifed successfully")
	return nil
}

// pass nil as common.EnclaveConfig for non-sgx
func NewMasterkeyStore(nodeInfo *common.NodeInfo, keyFolder string, config *common.EnclaveConfig) common.MasterKeyStore {
	file := filepath.Join(keyFolder, nodeInfo.Id)
	ks := &MasterKeyStore{
		File:             file,
		ConfiguredNodeId: nodeInfo,
		hasSGX:           config != nil,
	}

	return ks
}

func (ks *MasterKeyStore) Read() *common.Member {
	if ks.cachedMasterkey != nil {
		return ks.cachedMasterkey
	}
	content, err := os.ReadFile(ks.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var plain []byte
	if ks.hasSGX {
		var e []byte
		plain, err = ecrypto.Unseal(content, e)
	} else {
		plain = content
	}
	if err != nil {
		panic(err)
	}
	var m common.Member
	err = json.Unmarshal(plain, &m)
	if err != nil {
		panic(err)
	}
	ks.cachedMasterkey = &m
	return &m
}

func (ks *MasterKeyStore) Write(secret *common.MasterSecret) {
	m := &common.Member{NodeInfo: ks.ConfiguredNodeId, MasterSecret: secret}
	json, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var sealed []byte
	if ks.hasSGX {
		var e []byte
		sealed, err = ecrypto.SealWithProductKey(json, e)
	} else {
		sealed = json
	}
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(ks.File, sealed, fs.ModePerm)
	if err != nil {
		panic(err)
	}
}

func ValidateSignedQuote(quote []byte) (*common.SGXReport, error) {
	report, err := enclave.VerifyRemoteReport(quote)
	if err != nil && len(report.Data) == 0 {
		return nil, err
	}
	if report.TCBAdvisoriesErr != nil || err != nil {
		slog.Warn("report.TCBAdvisoriesErr", "error", report.TCBAdvisoriesErr)
		slog.Warn("enclave.VerifyRemoteReport", "error", err)
	}

	var tcbErr = ""
	if report.TCBAdvisoriesErr != nil {
		tcbErr = report.TCBAdvisoriesErr.Error()
	}
	sgxRep := &common.SGXReport{
		Data:             hex.EncodeToString(report.Data),
		ProductID:        binary.LittleEndian.Uint16(report.ProductID),
		SecurityVersion:  report.SecurityVersion,
		Debug:            report.Debug,
		UniqueID:         hex.EncodeToString(report.UniqueID),
		SignerID:         hex.EncodeToString(report.SignerID),
		TCBStatus:        report.TCBStatus.String(),
		TCBAdvisories:    report.TCBAdvisories,
		TCBAdvisoriesErr: tcbErr,
	}
	return sgxRep, err
}
