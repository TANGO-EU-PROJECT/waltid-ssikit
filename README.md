# SSIKIT Tool Modification

This project modifies the SSIKIT tool to deploy the following components:

- Issuer
- Verifier
- Web Wallet

## Installation

Follow the steps below to set up the necessary environment to use the project's components.

### Hosts Configuration

Modify the `/etc/hosts` file to add the following paths as localhost:

```
127.0.0.1 localhost umu-issuer umu-webWallet umu-verifier
```

### HTTPS Certificates Import

The `/cert` folder contains 3 directories for importing the certificate of each component.

#### Import to JDK:

Execute the following command to import the certificates to the JDK:

```bash
sudo keytool -import -alias <NAME> -file <NAME>.crt -keystore /usr/lib/jvm/<YOUR_VERSION>/lib/security/cacerts -storepass changeit
```

- Verifier name -> `verifier`
- Issuer name -> `issuer`
- Web wallet name -> `webWallet`

#### Import to Browser:

You must add the 3 certificates within your browser's list of trusted certificates.

#### Manual Import:

Since these are self-signed certificates, you must manually trust them by accessing the following websites:

- [https://umu-issuer:8443](https://umu-issuer:8443)
- [https://umu-verifier:8444](https://umu-verifier:8444)
- [https://umu-webWallet:8445](https://umu-webWallet:8445)

### OPA Installation for Policy Management

Install OPA to manage security policies with the following command:

```bash
curl -L -o opa https://openpolicyagent.org/downloads/v0.62.1/opa_linux_amd64_static
chmod 755 ./opa
mv opa /usr/bin
```

### HYPERLEDGER

The current version is intended to use a `hyperledger fabric` blockchain for uploading and querying DIDs. 

To view the demo without the need to have the Hyperledger blockchain running, the code includes some static DIDs, which are also stored in the tool's internal storage.

Four classes of the tool: `IssuerServer.kt, VerifierServer.kt, WebWallet.kt, WaltIdJsonLdCredentialService.kt` have a global variable called **"local"**, which must be set to **"true"** to perform tests without Hyperledger running.
### USAGE

To see the commands with their options:

```bash
./ssikit.sh --help
```

Launch all services `(issuer, verifier, and web wallet)`

```bash
./ssikit fullApi
```
