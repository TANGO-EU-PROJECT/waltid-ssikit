package id.walt.services.did.factories

import id.walt.crypto.*
import id.walt.model.Did
import id.walt.model.DidUrl
import id.walt.services.did.DidOptions
import id.walt.services.did.composers.DidKeyDocumentComposerUmu
import id.walt.services.did.composers.models.DocumentComposerBaseParameter
import java.util.*
import org.bitcoinj.core.Base58

class DidKeyFactoryUmu(
    private val documentComposer: DidKeyDocumentComposerUmu,
) : DidFactoryUmu {
    override fun create(keyumu: KeyUmu, key: Key?, options: DidOptions?): Did {
        return documentComposer.makeKeyId(DocumentComposerBaseParameter(DidUrl.from(publicKeyToDidKeyBase58(keyumu.publicKey.getEncoded()))), keyumu)
    }

    override fun createMultiKey(key: Key, keys: Int, options: DidOptions?): Did {
        TODO("Not yet implemented")
    }

    fun publicKeyToDidKeyBase58(publicKeyBytes: ByteArray): String {
        val encodedKey = Base58.encode(publicKeyBytes)
        return "did:keyumu:$encodedKey"
    }

}
