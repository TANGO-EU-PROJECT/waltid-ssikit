package id.walt.services.did.composers

import com.beust.klaxon.Klaxon
import id.walt.crypto.LdVerificationKeyType
import id.walt.crypto.convertMultiBase58BtcToRawKey
import id.walt.crypto.encodeBase58
import id.walt.crypto.getMultiCodecKeyCode
import id.walt.model.DID_CONTEXT_URL
import id.walt.model.DidUrl
import id.walt.model.VerificationMethod
import id.walt.model.did.DidEbsi
import id.walt.services.did.composers.models.DocumentComposerBaseParameter
import id.walt.services.did.composers.models.DocumentComposerKeyJwkParameter
import id.walt.model.did.DidFabric
import id.walt.services.did.composers.models.DocumentComposerBaseFabric
import id.walt.services.did.composers.models.DocumentComposerJwkParameter

class DidFabricDocumentComposer : DidDocumentComposeBaseFabric<DidFabric>() {
    override fun make(fabric: DocumentComposerBaseFabric, key: DocumentComposerBaseParameter, id: String): DidFabric {

        val pubKey = convertMultiBase58BtcToRawKey(key.didUrl.identifier)

        return DidFabric(
            context = listOf("https://w3id.org/did/v1"),
            id = fabric.didUrl.did,
            verificationMethod = listOf(
                VerificationMethod(
                    id = fabric.didUrl.did+"#"+fabric.id,
                    type = "PsmsBlsSignature2022",
                    controller = fabric.didUrl.did,
                    publicKeyBase58 = fabric.publicKey58
                ),
                VerificationMethod(
                    id = fabric.didUrl.did+"#"+id,
                    type = LdVerificationKeyType.Ed25519VerificationKey2019.name,
                    controller = fabric.didUrl.did,
                    publicKeyBase58 = pubKey.encodeBase58()
                ),
            ),
            authentication = listOf(VerificationMethod.Reference(fabric.didUrl.did+"#"+id)),
            assertionMethod = listOf(VerificationMethod.Reference(fabric.didUrl.did+"#"+fabric.id))
        )
    }

    override fun make_multikey(
        fabrics: List<DocumentComposerBaseFabric>,
        key: DocumentComposerBaseParameter,
        identifier: String
    ): DidFabric {
        val pubKey = convertMultiBase58BtcToRawKey(key.didUrl.identifier)
        val verificationMethods = mutableListOf<VerificationMethod>()
        for (fabric in fabrics) {
            verificationMethods.add(
                VerificationMethod(
                    id = fabrics.first().didUrl.did + "#" + fabric.id,
                    type = "PsmsBlsSignature2022",
                    controller = fabrics.first().didUrl.did,
                    publicKeyBase58 = fabric.publicKey58
                )
            )
        }

        val  assertionMethod = verificationMethods.map { VerificationMethod.Reference(it.id) }

        // Añadir un VerificationMethod para el parámetro key
        verificationMethods.add(
            VerificationMethod(
                id = fabrics.first().didUrl.did + "#" + identifier, // Usa el DID del primer elemento como base
                type = LdVerificationKeyType.Ed25519VerificationKey2019.name,
                controller = fabrics.first().didUrl.did,
                publicKeyBase58 = pubKey.encodeBase58()
            )
        )

        return DidFabric(
            context = listOf("https://w3id.org/did/v1"),
            id = fabrics.first().didUrl.did, // Asume que todos los fabrics tienen el mismo DID base
            verificationMethod = verificationMethods,
            authentication = listOf(VerificationMethod.Reference(fabrics.first().didUrl.did + "#" + identifier)),
            assertionMethod = assertionMethod
        )
    }

}
