package id.walt.services.did.factories

import com.beust.klaxon.Klaxon
import id.walt.common.convertToRequiredMembersJsonString
import id.walt.crypto.*
import id.walt.model.Did
import id.walt.model.DidUrl
import id.walt.model.did.DidFabric
import id.walt.services.did.DidKeyCreateOptions
import id.walt.services.did.DidOptions
import id.walt.services.did.DidService
import id.walt.services.did.composers.DidDocumentComposer
import id.walt.services.did.composers.DidDocumentComposerFabric
import id.walt.services.did.composers.models.DocumentComposerBaseFabric
import id.walt.services.did.composers.models.DocumentComposerBaseParameter
import id.walt.services.did.composers.models.DocumentComposerJwkParameter
import id.walt.services.did.composers.models.DocumentComposerKeyJwkParameter
import id.walt.services.key.KeyService
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.keystore.KeyType
import id.walt.services.storeUmu.KeyStoreServiceUmu
import org.bitcoinj.core.Base58
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.erdtman.jcs.JsonCanonicalizer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*

class DidFabricFactory(
    private val keyService: KeyService,
    private val documentComposer: DidDocumentComposerFabric<DidFabric>,

) : DidFactoryUmu  {

    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()
    override fun create(keyumu: KeyUmu, key: Key?, options: DidOptions?): Did {

        if (key != null){
            if (key.algorithm !in setOf(
                    KeyAlgorithm.EdDSA_Ed25519, KeyAlgorithm.RSA, KeyAlgorithm.ECDSA_Secp256k1, KeyAlgorithm.ECDSA_Secp256r1
                )
            ) throw IllegalArgumentException("did:fabric can not be created with an ${key.algorithm} key.")
            val identifierComponents = getIdentifierComponents(key, options as? DidKeyCreateOptions)
            val identifier = convertRawKeyToMultiBase58Btc(identifierComponents.pubKeyBytes, identifierComponents.multiCodecKeyCode)
            val document_key =DocumentComposerBaseParameter(DidUrl.from("did:key:$identifier"))
            val document_fabric =DocumentComposerBaseFabric(DidUrl.from(getDidUrl(keyumu.publicKey.getEncoded())),publicKeyToDidKeyBase58(keyumu.publicKey.getEncoded()),keyumu.KeyIdUmu.id)
            return documentComposer.make(document_fabric,document_key,key.keyId.id)
        }
        else
        {
            throw IllegalArgumentException("did:fabric need a key value")
        }

    }

    override fun createMultiKey(key: Key, keys: Int, options: DidOptions?): Did {

        if (key != null){
            if (key.algorithm !in setOf(
                    KeyAlgorithm.EdDSA_Ed25519, KeyAlgorithm.RSA, KeyAlgorithm.ECDSA_Secp256k1, KeyAlgorithm.ECDSA_Secp256r1
                )
            ) throw IllegalArgumentException("did:fabric can not be created with an ${key.algorithm} key.")

            val documentComposers = mutableListOf<DocumentComposerBaseFabric>()

            for (i in 1..keys) {
                val hashSet = HashSet<String>()
                for (j in 1..i) {
                    hashSet.add(j.toString())
                }
                val kid_fabric = keyServiceUmu.generate(hashSet)

                keyStoreUmu.addAlias(kid_fabric, kid_fabric.id)
                val keyUmu = DidService.KeyServiceUmu.load(kid_fabric.toString());
                val document_fabric = DocumentComposerBaseFabric(
                    DidUrl.from(getDidUrl(keyUmu.publicKey.getEncoded())),
                    publicKeyToDidKeyBase58(keyUmu.publicKey.getEncoded()),
                    keyUmu.KeyIdUmu.id
                )
                documentComposers.add(document_fabric)
            }


            val identifierComponents = getIdentifierComponents(key, options as? DidKeyCreateOptions)
            val identifier = convertRawKeyToMultiBase58Btc(identifierComponents.pubKeyBytes, identifierComponents.multiCodecKeyCode)
            val document_key =DocumentComposerBaseParameter(DidUrl.from("did:key:$identifier"))
            return documentComposer.make_multikey(documentComposers,document_key,key.keyId.id)
        }
        else
        {
            throw IllegalArgumentException("did:fabric need a key value")
        }

    }

    fun publicKeyToDidKeyBase58(publicKeyBytes: ByteArray): String {
        val encodedKey = Base58.encode(publicKeyBytes)
        return encodedKey

    }

    fun getDidUrl(publicKeyBytes: ByteArray): String {
        val didurl = publicKeyToDidKeyBase58(publicKeyBytes).sha256()
        return "did:fabric:$didurl"
    }

    fun generarValorAleatorio(): String {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        val randomvalue = base64String.substring(0, 16) + "-" + base64String.substring(16)
        return randomvalue
    }

    private fun String.sha256(): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }










    // DID KEY

    private fun getIdentifierComponents(key: Key, options: DidKeyCreateOptions?): IdentifierComponents =
        options?.takeIf { it.useJwkJcsPub }?.let {
            IdentifierComponents(JwkJcsPubMultiCodecKeyCode, getJwkPubKeyRequiredMembersBytes(key))
        } ?: IdentifierComponents(getMulticodecKeyCode(key.algorithm), getPublicKeyBytesForDidKey(key))

    private fun getJwkPubKeyRequiredMembersBytes(key: Key) = JsonCanonicalizer(
        Klaxon().toJsonString(
            convertToRequiredMembersJsonString(
                keyService.toJwk(
                    key.keyId.id,
                    KeyType.PUBLIC
                )
            )
        )
    ).encodedUTF8

    private fun getPublicKeyBytesForDidKey(key: Key): ByteArray = when (key.algorithm) {
        KeyAlgorithm.ECDSA_Secp256k1, KeyAlgorithm.ECDSA_Secp256r1 -> (key.getPublicKey() as BCECPublicKey).q.getEncoded(
            true
        )

        KeyAlgorithm.RSA, KeyAlgorithm.EdDSA_Ed25519 -> key.getPublicKeyBytes()
    }

    data class IdentifierComponents(
        val multiCodecKeyCode: UInt,
        val pubKeyBytes: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as IdentifierComponents

            if (multiCodecKeyCode != other.multiCodecKeyCode) return false
            if (!pubKeyBytes.contentEquals(other.pubKeyBytes)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = multiCodecKeyCode.hashCode()
            result = 31 * result + pubKeyBytes.contentHashCode()
            return result
        }
    }


}
