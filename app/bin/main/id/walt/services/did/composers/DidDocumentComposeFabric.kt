package id.walt.services.did.composers

import id.walt.model.Did
import id.walt.services.did.composers.models.DocumentComposerBaseFabric
import id.walt.services.did.composers.models.DocumentComposerBaseParameter

interface DidDocumentComposerFabric<T : Did> {
    fun make(fabric: DocumentComposerBaseFabric, key: DocumentComposerBaseParameter, identifier: String): T
    fun make_multikey(fabric: List<DocumentComposerBaseFabric>, key: DocumentComposerBaseParameter, identifier: String): T
}
