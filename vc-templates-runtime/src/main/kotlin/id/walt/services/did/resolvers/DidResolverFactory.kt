package id.walt.services.did.resolvers

import id.walt.model.Did
import id.walt.model.DidMethod
import id.walt.model.did.DidEbsi
import id.walt.model.did.DidFabric
import id.walt.model.did.DidKey
import id.walt.services.WaltIdServices
import id.walt.services.did.composers.DidDocumentComposer
import id.walt.services.did.composers.DidDocumentComposerFabric
import id.walt.services.did.composers.DidKeyDocumentComposerUmu
import id.walt.services.ecosystems.iota.IotaWrapper
import id.walt.services.key.KeyService
import io.ktor.client.*

class DidResolverFactory(
    private val httpNoAuth: HttpClient = WaltIdServices.httpNoAuth,
    private val httpAuth: HttpClient = WaltIdServices.httpWithAuth,
    private val keyService: KeyService,
    private val iotaWrapper: IotaWrapper,
    private val didKeyDocumentComposer: DidDocumentComposer<DidKey>,
    private val didKeyUmuDocumentComposer: DidDocumentComposer<DidKey>,
    private val didJwkDocumentComposer: DidDocumentComposer<Did>,
    private val ebsiV2DocumentComposer: DidDocumentComposer<DidEbsi>,
    private val didFabricDocumentCompose: DidDocumentComposerFabric<DidFabric>
) {

    fun create(didMethod: String): DidResolver {
        return when (DidMethod.valueOf(didMethod)) {
            DidMethod.key -> DidKeyResolver(didKeyDocumentComposer)
            DidMethod.web -> DidWebResolver(httpNoAuth)
            DidMethod.ebsi -> DidEbsiResolver(httpNoAuth, keyService, ebsiV2DocumentComposer)
            DidMethod.jwk -> DidJwkResolver(didJwkDocumentComposer)
            DidMethod.iota -> DidIotaResolver(iotaWrapper)
            DidMethod.keyumu -> DidKeyResolverUmu(didKeyUmuDocumentComposer)
            DidMethod.cheqd -> DidCheqdResolver(HttpClient())//TODO: fix contentType for application/did+ld+json
            DidMethod.fabric -> DidFabricResolver()
        }
    }
}
