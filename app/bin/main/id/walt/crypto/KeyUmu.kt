package id.walt.crypto


import id.walt.services.keyUmu.KeyAlgorithmUmu
import id.walt.services.keystore.TinkKeyStoreService
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.ASN1BitString
import org.bouncycastle.asn1.ASN1Sequence

import inf.um.multisign.*;
import inf.um.psmultisign.PSprivateKey
import inf.um.psmultisign.PSverfKey;


@Serializable
data class KeyIdUmu(val id: String) { // TODO Make value class (performance)
    override fun toString() = id
}

data class KeyUmu(val KeyIdUmu: KeyIdUmu, val algorithm: KeyAlgorithmUmu, val privateKey: PSprivateKey?, val publicKey: PSverfKey) {
    fun getPublicKey(): ByteArray {
        return publicKey.getEncoded()
    }

    override fun toString(): String = "Key[${KeyIdUmu.id}; Algo: ${algorithm.name};]"


}
