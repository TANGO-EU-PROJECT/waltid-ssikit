package id.walt.services.keyUmu

import id.walt.crypto.*
import id.walt.servicematrix.ServiceProvider
import id.walt.services.WaltIdService
import id.walt.services.storeUmu.KeyStoreServiceUmu


enum class KeyAlgorithmUmu {
    PsmsBlsSignature2022,
    RSA;

}

private val keyStoreUmu = KeyStoreServiceUmu.getService()

abstract class KeyServiceUmu : WaltIdService() {
    override val implementation get() = serviceImplementation<KeyServiceUmu>()

    open fun deleteAll(): Unit = keyStoreUmu.deleteAll()
    open fun generate(attr: Set<String>): KeyIdUmu = implementation.generate(attr)

    open fun addAlias(KeyIdUmu: KeyIdUmu, alias: String): Unit = implementation.addAlias(KeyIdUmu, alias)

    open fun load(keyAlias: String): KeyUmu = implementation.load(keyAlias)

    open fun export(
        keyAlias: String
    ): String =
        implementation.export(keyAlias)

    open fun importKey(keyStr: String): KeyIdUmu? = implementation.importKey(keyStr)

    open fun listKeys(): List<KeyUmu> = implementation.listKeys()

    open fun delete(alias: String): Unit = implementation.delete(alias)

    open fun hasKey(alias: String): Boolean = implementation.hasKey(alias)


    companion object : ServiceProvider {
        override fun getService() = object : KeyServiceUmu() {}
        override fun defaultImplementation() = WaltIdKeyServiceUmu()
    }
}
