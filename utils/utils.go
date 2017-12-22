package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	bccspSigner "github.com/hyperledger/fabric/bccsp/signer"
	"github.com/hyperledger/fabric/bccsp/sw"
	"io/ioutil"
	"os"
)

func LoadPublicKey(file *os.File) (publicKey bccsp.Key, err error) {
	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
		},
	}

	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		return
	}

	privatePem, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	p, _ := pem.Decode(privatePem)

	publicKey, err = csp.KeyImport(p.Bytes, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: true})

	return
}

func LoadPrivateKey(file *os.File) (privateKey bccsp.Key,
	signer crypto.Signer, err error) {
	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
		},
	}

	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		return
	}

	privatePem, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	p, _ := pem.Decode(privatePem)

	privateKey, err = csp.KeyImport(p.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
	if err != nil {
		return
	}

	signer, err = bccspSigner.New(csp, privateKey)

	return
}

// GeneratePrivateKey creates a private key and stores it in keystorePath
func GeneratePrivateKey(keystorePath string) (bccsp.Key,
	crypto.Signer, error) {

	var err error
	var priv bccsp.Key
	var s crypto.Signer

	opts := &factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}
	csp, err := factory.GetBCCSPFromOpts(opts)
	if err == nil {
		// generate a key
		priv, err = csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
		if err == nil {
			// create a crypto.Signer
			s, err = bccspSigner.New(csp, priv)
		}
	}

	return priv, s, err
}

func GetECPublicKey(privateKey bccsp.Key) (*ecdsa.PublicKey, error) {
	// get the public key
	pubKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, err
	}
	// marshal to bytes
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}
	// unmarshal using pkix
	ecPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return ecPubKey.(*ecdsa.PublicKey), nil
}

func StoreKey(storePath string, key bccsp.Key) (err error) {
	ks, err := sw.NewFileBasedKeyStore(nil, storePath, false)
	err = ks.StoreKey(key)

	return
}
