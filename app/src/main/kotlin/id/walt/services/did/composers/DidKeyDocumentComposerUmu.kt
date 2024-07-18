package id.walt.services.did.composers

import com.beust.klaxon.Klaxon
import com.nimbusds.jose.jwk.JWK
import id.walt.crypto.KeyUmu
import id.walt.crypto.convertMultiBase58BtcToRawKey
import id.walt.crypto.getMultiCodecKeyCode
import id.walt.model.VerificationMethod
import id.walt.model.did.DidKey
import id.walt.services.OIDC_UMU.sha256
import id.walt.services.did.composers.models.DocumentComposerBaseParameter
import java.util.*

class DidKeyDocumentComposerUmu : DidDocumentComposerBase<DidKey>() {

    override fun make(parameter: DocumentComposerBaseParameter): DidKey {
        val id = parameter.didUrl.did.substringAfter("did:keyumu:").sha256()
        val it = "${parameter.didUrl.did}#$id"
        return DidKey(
            context = listOf(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ),
            id = parameter.didUrl.did,
            verificationMethod = listOf(
                VerificationMethod(
                    id = it,
                    type = "PsmsBlsSignature2022",
                    controller = parameter.didUrl.did,
                    publicKeyBase58 = parameter.didUrl.did.substringAfter("did:keyumu:")
                )
            ),
            assertionMethod = listOf(VerificationMethod.Reference(it)),
            authentication = listOf(VerificationMethod.Reference(it)),
            capabilityInvocation = listOf(VerificationMethod.Reference(it)),
            capabilityDelegation = listOf(VerificationMethod.Reference(it)),
        )
    }

    fun makeKeyId(parameter: DocumentComposerBaseParameter, keyUmu: KeyUmu): DidKey {
        val it = "${parameter.didUrl.did}#${keyUmu.KeyIdUmu.id}"
        return DidKey(
            context = listOf(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ),
            id = parameter.didUrl.did,
            verificationMethod = listOf(
                VerificationMethod(
                    id = it,
                    type = "PsmsBlsSignature2022",
                    controller = parameter.didUrl.did,
                    publicKeyBase58 = parameter.didUrl.did.substringAfter("did:keyumu:")
                )
            ),
            assertionMethod = listOf(VerificationMethod.Reference(it)),
            authentication = listOf(VerificationMethod.Reference(it)),
            capabilityInvocation = listOf(VerificationMethod.Reference(it)),
            capabilityDelegation = listOf(VerificationMethod.Reference(it)),
        )

    }


}


