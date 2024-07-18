package id.walt.services.keyUmu


import id.walt.crypto.*
import id.walt.services.context.ContextManager
import id.walt.services.crypto.CryptoService

import id.walt.services.storeUmu.KeyStoreServiceUmu
import inf.um.multisign.MS
import inf.um.multisign.MSauxArg
import inf.um.psmultisign.PSauxArg
import inf.um.psmultisign.PSms
import inf.um.psmultisign.PSprivateKey
import inf.um.psmultisign.PSverfKey
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.bitcoinj.core.Base58
import java.security.MessageDigest
import java.util.*
import kotlin.collections.HashSet


class WaltIdKeyServiceUmu: KeyServiceUmu() {

    open val cryptoService: CryptoService = CryptoService.getService()

    open val keyStoreUmu: KeyStoreServiceUmu
        get() = ContextManager.keyStoreUmu

    override fun generate(attr: Set<String>): KeyIdUmu {
        val psScheme: MS = PSms()
        val PAIRING_NAME = "inf.um.pairingBLS461.PairingBuilderBLS461"
        val auxArg: MSauxArg = PSauxArg(PAIRING_NAME, attr)
        psScheme.setup(1, auxArg, UUID.randomUUID().toString().replace("-", "").toByteArray())
        val keysJavaPair = psScheme.kg()
        val keysKotlinPair = Pair(keysJavaPair.first, keysJavaPair.second)
        val (privateKey, verificationKey) = keysKotlinPair
        val keyid = KeyIdUmu(UUID.randomUUID().toString().replace("-", ""))
        keyStoreUmu.store(KeyUmu(keyid, KeyAlgorithmUmu.PsmsBlsSignature2022, privateKey as PSprivateKey, verificationKey as PSverfKey))
        keyStoreUmu.addAlias(keyid, Base58.encode(verificationKey.getEncoded()).sha256())
        return keyid;
    }

    private  fun String.sha256(): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }


    override fun addAlias(keyIdUmu: KeyIdUmu, alias: String) = keyStoreUmu.addAlias(keyIdUmu, alias)

    override fun load(keyAlias: String): KeyUmu = keyStoreUmu.load(keyAlias)

    override fun export(keyAlias: String): String {

        val key = keyStoreUmu.load(keyAlias)

        val private: String
        if((key.privateKey) == null)
            private = ""
        else{
            private = Base58.encode((key.privateKey).getEncoded())
        }
        val public = Base58.encode((key.publicKey).getEncoded())

        val payload = buildJsonObject {
            put("kty", "PSMS")
            put("use", "sig")
            put("algo", "PSMS")
            put("kid", key.KeyIdUmu.toString())
            put("public", public)
            put("private", private)
        }.toString()

        return payload
    }

    override fun importKey(keyStr: String): KeyIdUmu? {

        val jsonElement = Json.parseToJsonElement(keyStr)
        if (!jsonElement.jsonObject.containsKey("public") ||
            !jsonElement.jsonObject.containsKey("kty") ||
            !jsonElement.jsonObject.containsKey("kid"))  return null

        val privateEncoded = jsonElement.jsonObject["private"]?.toString()?.removeSurrounding("\"") ?: return null
        val publicEncoded = jsonElement.jsonObject["public"]?.toString()?.removeSurrounding("\"") ?: return null
        val kid = jsonElement.jsonObject["kid"]?.toString()?.removeSurrounding("\"") ?: return null
        val keyIdUmu =  KeyIdUmu(kid)

        val public = PSverfKey(Base58.decode(publicEncoded))

        val private = if (!privateEncoded.isNullOrEmpty()) {
            PSprivateKey(Base58.decode(privateEncoded))
        } else {
            null
        }

        keyStoreUmu.store(KeyUmu(keyIdUmu, KeyAlgorithmUmu.PsmsBlsSignature2022, private, public))
        keyStoreUmu.addAlias(keyIdUmu,keyIdUmu.id)
        return keyIdUmu
    }


    override fun listKeys(): List<KeyUmu> = keyStoreUmu.listKeys()

    override fun delete(alias: String) = keyStoreUmu.delete(alias)

    override fun hasKey(alias: String): Boolean = keyStoreUmu.getKeyId(alias) != null
}
