# cryptotool
An crypto tool to generate key and sign certification

## Generate public and private keypair

Using this command to generate keypair
```bash
./cryptotool genKey
```
The keypair will store in dir "temp" of current work path


## Sign certification file

CA can using this command to sign certification file

How to use:
- CACert: The certification file of CA
- CAKey: The private key of CA
- pubKey: User's public key
- mode: Enum(tls or sign)
- sans: multi strings, the DNS of user, only used in tls certification

The result will store in dir "temp/signcerts" or "temp/tlscerts" of current work path

### Sign normal certification file
```bash
./cryptotool sign --CACert="CA's certification file" --CAKey="CA's private key" --pubKey="User's public key" --mode=sign --name="User's common name"
```

### Sign tls certification file
```bash
./cryptotool sign --CACert="CA's certification file" --CAKey="CA's private key" --pubKey="User's public key" --mode=tls --name="User's common name" --sans="peer1.org1.example.com" --sans="peer1"
```
