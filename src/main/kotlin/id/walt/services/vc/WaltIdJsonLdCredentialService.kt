package id.walt.services.vc

import com.apicatalog.jsonld.JsonLdErrorCode
import com.danubetech.keyformats.crypto.provider.Ed25519Provider
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDException
import foundation.identity.jsonld.JsonLDObject
import id.walt.auditor.VerificationPolicyResult
import id.walt.credentials.jsonld.JsonLdDocumentLoaderService
import id.walt.credentials.w3c.*
import id.walt.credentials.w3c.schema.SchemaValidatorFactory
import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.LdSignatureType
import id.walt.crypto.LdSigner
import id.walt.services.context.ContextManager
import id.walt.services.did.DidService
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.SqlKeyStoreService
import id.walt.services.keystore.TinkKeyStoreService
import id.walt.services.storeUmu.KeyStoreServiceUmu
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts
import info.weboftrust.ldsignatures.signer.PsmsBlsSignature2022LdSigner
import info.weboftrust.ldsignatures.signer.PsmsBlsSignatureProof2022LdProver
import info.weboftrust.ldsignatures.util.PsmsBlsUmuUtil
import info.weboftrust.ldsignatures.verifier.LdVerifier
import info.weboftrust.ldsignatures.verifier.PsmsBlsSignature2022LdVerifier
import info.weboftrust.ldsignatures.verifier.PsmsBlsSignatureProof2022LdVerifier
import mu.KotlinLogging
import org.json.JSONObject
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.time.Instant
import java.util.*

private val log = KotlinLogging.logger {}

open class WaltIdJsonLdCredentialService : JsonLdCredentialService() {



    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyStore = SqlKeyStoreService()

    val local = true

    private val documentLoaderService: JsonLdDocumentLoaderService get() = JsonLdDocumentLoaderService.getService()

    init {
        Ed25519Provider.set(TinkEd25519Provider())
    }

    private fun selectLdSigner(config: ProofConfig, key: Key): info.weboftrust.ldsignatures.signer.LdSigner<*> {
        return if (config.ldSignatureType != null) {
            when (config.ldSignatureType) {
                LdSignatureType.EcdsaSecp256k1Signature2019 -> {
                    require(key.algorithm == KeyAlgorithm.ECDSA_Secp256k1) { "Unsupported key algorithm ${key.algorithm} for ld signature type ${config.ldSignatureType}" }
                    LdSigner.EcdsaSecp256K1Signature2019(key.keyId)
                }

                LdSignatureType.Ed25519Signature2018 -> {
                    require(key.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm ${key.algorithm} for ld signature type ${config.ldSignatureType}" }
                    LdSigner.Ed25519Signature2018(key.keyId)
                }

                LdSignatureType.Ed25519Signature2020 -> {
                    require(key.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm ${key.algorithm} for ld signature type ${config.ldSignatureType}" }
                    LdSigner.Ed25519Signature2020(key.keyId)
                }

                LdSignatureType.JcsEd25519Signature2020 -> {
                    require(key.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm ${key.algorithm} for ld signature type ${config.ldSignatureType}" }
                    LdSigner.JcsEd25519Signature2020(key.keyId)
                }

                LdSignatureType.JsonWebSignature2020 -> LdSigner.JsonWebSignature2020(key.keyId)
                LdSignatureType.RsaSignature2018 -> {
                    require(key.algorithm == KeyAlgorithm.RSA) { "Unsupported key algorithm ${key.algorithm} for ld signature type ${config.ldSignatureType}" }
                    LdSigner.RsaSignature2018(key.keyId)
                }
                LdSignatureType.PsmsBlsSignature2022 -> TODO()
                LdSignatureType.PsmsBlsSignature2022Proof -> TODO()
            }
        } else {
            LdSigner.JsonWebSignature2020(key.keyId)
        }
    }

    private fun selectLdVerifier(ldSignatureType: LdSignatureType, publicKey: Key): LdVerifier<*> {
        return when (ldSignatureType) {
            LdSignatureType.RsaSignature2018 -> {
                require(publicKey.algorithm == KeyAlgorithm.RSA) { "Unsupported key algorithm ${publicKey.algorithm} for ld signature type $ldSignatureType" }
                id.walt.crypto.LdVerifier.RsaSignature2018(publicKey)
            }

            LdSignatureType.JcsEd25519Signature2020 -> {
                require(publicKey.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm ${publicKey.algorithm} for ld signature type $ldSignatureType" }
                id.walt.crypto.LdVerifier.JcsEd25519Signature2020(publicKey)
            }

            LdSignatureType.Ed25519Signature2020 -> {
                require(publicKey.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm ${publicKey.algorithm} for ld signature type $ldSignatureType" }
                id.walt.crypto.LdVerifier.Ed25519Signature2020(publicKey)
            }

            LdSignatureType.Ed25519Signature2018 -> {
                require(publicKey.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm ${publicKey.algorithm} for ld signature type $ldSignatureType" }
                id.walt.crypto.LdVerifier.Ed25519Signature2018(publicKey)
            }

            LdSignatureType.EcdsaSecp256k1Signature2019 -> {
                require(publicKey.algorithm == KeyAlgorithm.ECDSA_Secp256k1) { "Unsupported key algorithm ${publicKey.algorithm} for ld signature type $ldSignatureType" }
                id.walt.crypto.LdVerifier.EcdsaSecp256k1Signature2019(publicKey)
            }

            LdSignatureType.JsonWebSignature2020 -> id.walt.crypto.LdVerifier.JsonWebSignature2020(publicKey)

            LdSignatureType.PsmsBlsSignature2022 -> TODO()
            LdSignatureType.PsmsBlsSignature2022Proof -> TODO()
        }
    }



    override fun sign(jsonCred: String, config: ProofConfig): String {
        log.debug { "Signing jsonLd object with: issuerDid (${config.issuerDid}), domain (${config.domain}), nonce (${config.nonce}" }

        val jsonLdObject: JsonLDObject = JsonLDObject.fromJson(jsonCred)
        val confLoader = documentLoaderService.documentLoader as ConfigurableDocumentLoader
        confLoader.isEnableHttp = true
        confLoader.isEnableHttps = true
        confLoader.isEnableFile = true
        confLoader.isEnableLocalCache = true
        jsonLdObject.documentLoader = documentLoaderService.documentLoader
        val vm = config.issuerVerificationMethod ?: config.issuerDid
        val signer: info.weboftrust.ldsignatures.signer.LdSigner<*>;


        if (config.ldSignatureType == LdSignatureType.PsmsBlsSignature2022 ) {
            val keyUmu = keyStoreUmu.load(vm.substringAfter('#'))
            signer = PsmsBlsSignature2022LdSigner(keyUmu.privateKey);

        } else {
            val key = keyStore.load(vm)
            signer = selectLdSigner(config, key)
        }

        signer.creator = config.creator?.let { URI.create(it) }
        signer.created = Date() // Use the current date
        signer.domain = config.domain
        signer.nonce = config.nonce
        signer.verificationMethod = URI.create(config.issuerVerificationMethod ?: vm)
        signer.proofPurpose = config.proofPurpose

        log.debug { "Signing: $jsonLdObject" }
        try {
            signer.sign(jsonLdObject)
        } catch (ldExc: JsonLDException) {
            if (ldExc.code == JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED) {
                // if JSON LD remote context failed to load, retry once
                log.warn { "JSON LD remote context failed to load, retrying once..." }
                signer.sign(jsonLdObject)
            } else {
                throw ldExc
            }
        }
        return jsonLdObject.toJson(true)

    }

    private fun sign_deriveVC(jsonCred: String, config: ProofConfig, nonce: String, frame:String): String {
        val credential: JsonLDObject = JsonLDObject.fromJson(jsonCred)
        credential.documentLoader = LDSecurityContexts.DOCUMENT_LOADER

        val jsonLdObject = PsmsBlsUmuUtil.obtainFrameFromPresentation(credential, frame)


        jsonLdObject.documentLoader = LDSecurityContexts.DOCUMENT_LOADER
        val confLoader = documentLoaderService.documentLoader as ConfigurableDocumentLoader



        confLoader.isEnableHttp = true
        confLoader.isEnableHttps = true
        confLoader.isEnableFile = true
        confLoader.isEnableLocalCache = true
        jsonLdObject.documentLoader = documentLoaderService.documentLoader
        val vm = config.issuerVerificationMethod ?: config.issuerDid

        val signer: info.weboftrust.ldsignatures.signer.LdProver<*>;

        val keyUmu = keyStoreUmu.load(vm.substringAfter('#'))
        signer = PsmsBlsSignatureProof2022LdProver(keyUmu.publicKey,nonce,credential);

        signer.creator = config.creator?.let { URI.create(it) }
        signer.created = Date() // Use the current date
        signer.domain = config.domain
        signer.nonce = config.nonce
        signer.verificationMethod = URI.create(config.issuerVerificationMethod ?: vm)
        signer.proofPurpose = config.proofPurpose

        log.debug { "Signing: $jsonLdObject" }

        try {
            signer.sign(credential, jsonLdObject)
        } catch (ldExc: JsonLDException) {
            if (ldExc.code == JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED) {
                log.warn { "JSON LD remote context failed to load, retrying once..." }
                signer.sign(jsonLdObject, jsonLdObject)
            } else {
                throw ldExc
            }
        }

        jsonLdObject.setJsonObjectKeyValue("issuer", config.issuerDid)

        return jsonLdObject.toJson(true)

    }

    private fun getVerificationTypeFor(vcOrVp: VerifiableCredential): VerificationType = when (vcOrVp) {
        is VerifiablePresentation -> VerificationType.VERIFIABLE_PRESENTATION
        else -> VerificationType.VERIFIABLE_CREDENTIAL
    }

    override fun verify(vcOrVp: String): VerificationResult {
        val vcObj = vcOrVp.toVerifiableCredential()
        val issuer = vcObj.issuerId ?: throw NoSuchElementException("No issuer DID found for VC or VP")
        val vm = vcObj.proof?.verificationMethod ?: issuer

        if (!DidService.importKeys(issuer)) {
            throw IllegalArgumentException("Could not resolve verification keys")
        }

        log.debug { "Loading verification key for:  $vm" }


        val confLoader = documentLoaderService.documentLoader as ConfigurableDocumentLoader

        confLoader.isEnableHttp = true
        confLoader.isEnableHttps = true
        confLoader.isEnableFile = true
        confLoader.isEnableLocalCache = true

        log.debug { "Document loader config: isEnableHttp (${confLoader.isEnableHttp}), isEnableHttps (${confLoader.isEnableHttps}), isEnableFile (${confLoader.isEnableFile}), isEnableLocalCache (${confLoader.isEnableLocalCache})" }

        val jsonLdObject = JsonLDObject.fromJson(vcOrVp)
        jsonLdObject.documentLoader = documentLoaderService.documentLoader
        log.debug { "Decoded Json LD object: $jsonLdObject" }

        val ldProof = LdProof.getFromJsonLDObject(jsonLdObject)
        if (ldProof == null) {
            log.info { "No LD proof found on VC" }
            throw NoSuchElementException("No LD proof found on VC")
        }

        val ldSignatureType = LdSignatureType.valueOf(ldProof.type)
        val verifier: info.weboftrust.ldsignatures.verifier.LdVerifier<*>;

        if (ldSignatureType == LdSignatureType.PsmsBlsSignature2022) {

            val keyUmu = keyStoreUmu.load(vm)
            verifier = PsmsBlsSignature2022LdVerifier(keyUmu.publicKey);

        } else if (ldSignatureType == LdSignatureType.PsmsBlsSignature2022Proof) {

            var keyUmu = keyStoreUmu.load(vm)
            var nonce = ""
            if (vcObj.proof?.nonce !== null) nonce = vcObj.proof!!.nonce.toString()
            verifier = PsmsBlsSignatureProof2022LdVerifier(keyUmu.publicKey, nonce);
            val verificatioResult = try {
                verifier.verify(jsonLdObject,ldProof)
            } catch (ldExc: JsonLDException) {
                    throw ldExc
            }
            return VerificationResult(verificatioResult, getVerificationTypeFor(vcObj))
        }
        else {
            val publicKey = keyStore.load(vm)
            verifier = selectLdVerifier(ldSignatureType, publicKey)
        }

        log.debug { "Loaded Json LD verifier with signature suite: ${verifier.signatureSuite}" }

        val verificatioResult = try {
            verifier.verify(jsonLdObject)
        } catch (ldExc: JsonLDException) {
            if (ldExc.code == JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED) {
                // if JSON LD remote context failed to load, retry once
                log.warn { "JSON LD remote context failed to load, retrying once..." }
                verifier.verify(jsonLdObject)
            } else {
                throw ldExc
            }
        }

        log.debug { "Json LD verifier returned: $verificatioResult" }

        return VerificationResult(verificatioResult, getVerificationTypeFor(vcObj))
    }

    override fun addProof(credMap: Map<String, String>, ldProof: LdProof): String {
        val signedCredMap = HashMap<String, Any>(credMap)
        signedCredMap["proof"] = JSONObject(ldProof.toJson())
        return JSONObject(signedCredMap).toString()
    }

    override fun present(
        vcs: List<PresentableCredential>,
        holderDid: String,
        domain: String?,
        challenge: String?,
        expirationDate: Instant?
    ): String {
        log.debug { "Creating a presentation for VCs:\n$vcs" }


        val didSplit = holderDid.split(":")
        lateinit var verification: String
        if (didSplit[1] == "fabric") verification = DidService.getAuthenticationMethods(holderDid)!![0].id.substringAfter('#')
        else verification = DidService.getAuthenticationMethods(holderDid)!![0].id


        val id = "urn:uuid:${UUID.randomUUID()}"
        val config = ProofConfig(
            issuerDid = holderDid,
            issuerVerificationMethod = verification,
            proofPurpose = "authentication",
            proofType = ProofType.LD_PROOF,
            domain = domain,
            nonce = challenge,
            credentialId = id,
            expirationDate = expirationDate
        )
        val vpReqStr = VerifiablePresentationBuilder()
            .setId(id)
            .setHolder(holderDid)
            .setVerifiableCredentials(vcs)
            .build().toJson()

        log.trace { "VP request: $vpReqStr" }
        log.trace { "Proof config: $$config" }

        val vp = sign(vpReqStr, config)

        log.debug { "VP created:$vp" }
        return vp
    }

    override fun deriveVC(
        vc: String,
        issuer: String,
        domain: String?,
        challenge: String,
        expirationDate: Instant?,
        frame: String
    ): String {
        if (!local) DidService.importDidAndKeys(issuer)
        val id = "urn:uuid:${UUID.randomUUID()}"
        val config = ProofConfig(
            issuerDid = issuer,
            issuerVerificationMethod = DidService.getAssertonMethod(issuer)!![0].id,
            proofPurpose = "authentication",
            proofType = ProofType.LD_PROOF,
            domain = domain,
            ldSignatureType = LdSignatureType.PsmsBlsSignature2022Proof,
            nonce = challenge,
            credentialId = id,
            expirationDate = expirationDate
        )
        val vp = sign_deriveVC(vc,config,challenge,frame)

        log.debug { "VP created:$vp" }
        return vp
    }

    override fun listVCs(): List<String> {
        return Files.walk(Path.of("data/vc/created")).filter { Files.isRegularFile(it) }
            .filter { it.toString().endsWith(".json") }.map { it.fileName.toString() }.toList()
    }

    override fun validateSchema(vc: VerifiableCredential, schemaURI: URI) =
        SchemaValidatorFactory.get(schemaURI).validate(vc.toJson())

    override fun validateSchemaTsr(vc: String) = try {

        vc.toVerifiableCredential().let {

            if (it is VerifiablePresentation)
                return VerificationPolicyResult.success()

            val credentialSchemaUrl = it.credentialSchema?.id
                ?: return VerificationPolicyResult.failure(IllegalArgumentException("Credential has no associated credentialSchema property"))

            return validateSchema(it, URI.create(credentialSchemaUrl))
        }
    } catch (e: Exception) {
        VerificationPolicyResult.failure(e)
    }
}
