/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"path/filepath"

	"crypto/x509"
	"encoding/hex"
	"github.com/dilide/cryptotool/ca"
	"github.com/dilide/cryptotool/utils"
)

//command line flags
var (
	tempDir string
	app     = kingpin.New("cryptotool", "Utility for generating Hyperledger Fabric key material")

	genKey = app.Command("genKey", "generate private and public key")

	sign   = app.Command("sign", "Sign certificate using ca")
	CACert = sign.Flag("CACert", "The certificate of CA").Default("").File()
	CAKey  = sign.Flag("CAKey", "The private key of CA").Default("").File()
	pubKey = sign.Flag("pubKey", "The public key of peer").Default("").File()
	mode   = sign.Flag("mode", "tls or sign").Enum("sign", "tls")
	name   = sign.Flag("name", "The name of certification").Default("peer0.org0.example.com").String()
	sans   = sign.Flag("sans", "").Default("peer0", "peer0.org0.example.com").Strings()
)

func main() {
	kingpin.Version("0.0.1")

	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	tempDir = filepath.Join(dir, "temp")
	os.MkdirAll(tempDir, 0755)

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	case sign.FullCommand():
		signCert()

	case genKey.FullCommand():
		generateKey()
	}

}

func generateKey() {
	key, _, err := utils.GeneratePrivateKey(tempDir)
	if err != nil {
		panic(err)
	}

	os.Rename(filepath.Join(tempDir, hex.EncodeToString(key.SKI())+"_sk"), filepath.Join(tempDir, "private.pem"))

	pubKey, _ := key.PublicKey()
	utils.StoreKey(tempDir, pubKey)
	os.Rename(filepath.Join(tempDir, hex.EncodeToString(key.SKI())+"_pk"), filepath.Join(tempDir, "public.pem"))
}

func signCert() {
	c, err := ca.LoadCA(*CACert, *CAKey)
	if err != nil {
		panic(err)
	}

	pubKey, err := utils.LoadPublicKey(*pubKey)
	if err != nil {
		panic(err)
	}

	publicKey, err := utils.GetECPublicKey(pubKey)
	if err != nil {
		panic(err)
	}

	var cert *x509.Certificate

	if (*mode) == "sign" {
		signDir := filepath.Join(tempDir, "signcerts")
		os.RemoveAll(signDir)
		os.MkdirAll(signDir, 0755)

		cert, err = c.SignCertificate(signDir,
			*name, []string{}, publicKey, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{})
		if err != nil {
			panic(err)
		}

	} else {
		tlsDir := filepath.Join(tempDir, "tlscerts")
		os.RemoveAll(tlsDir)
		os.MkdirAll(tlsDir, 0755)

		cert, err = c.SignCertificate(tlsDir,
			*name, *sans, publicKey, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		if err != nil {
			panic(err)
		}
	}

	println(cert.Subject.CommonName)
}
