package id.walt.services.did.factories

import id.walt.crypto.Key
import id.walt.crypto.KeyUmu
import id.walt.model.Did
import id.walt.services.did.DidOptions

interface DidFactoryUmu {
    fun create(keyumu: KeyUmu, key: Key? = null, options: DidOptions? = null): Did
}
