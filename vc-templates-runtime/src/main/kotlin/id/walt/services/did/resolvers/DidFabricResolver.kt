package id.walt.services.did.resolvers

import id.walt.model.Did
import id.walt.model.DidUrl
import id.walt.model.did.DidFabric
import id.walt.services.did.DidOptions
import id.walt.services.ecosystems.fabric.VDR

class DidFabricResolver: DidResolverBase<DidFabric>() {
    override fun resolve(didUrl: DidUrl, options: DidOptions?): Did {
        val didDoc = VDR.getValue("did:fabric:"+didUrl.identifier)
        if (didDoc != null){
            return Did.decode(didDoc)?: throw Exception("Could not resolve $DidUrl")
        }
        else{
            throw Exception("Could not resolve $DidUrl")
        }

    }

}
