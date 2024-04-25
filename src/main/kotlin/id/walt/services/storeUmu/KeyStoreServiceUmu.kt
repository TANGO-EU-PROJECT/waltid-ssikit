package id.walt.services.storeUmu

import id.walt.crypto.Key
import id.walt.crypto.KeyId
import id.walt.crypto.KeyIdUmu
import id.walt.crypto.KeyUmu
import id.walt.servicematrix.ServiceProvider
import id.walt.services.WaltIdService
import id.walt.services.keystore.FileSystemKeyStoreService

enum class KeyType {
    PUBLIC,
    PRIVATE
}

abstract class KeyStoreServiceUmu : WaltIdService() {
    override val implementation get() = serviceImplementation<KeyStoreServiceUmu>()

    open fun store(key: KeyUmu): Unit = implementation.store(key)
    open fun load(alias: String): KeyUmu = implementation.load(alias)
    open fun addAlias(keyId: KeyIdUmu, alias: String): Unit = implementation.addAlias(keyId, alias)
    open fun delete(alias: String): Unit = implementation.delete(alias)
    open fun listKeys(): List<KeyUmu> = implementation.listKeys()

    open fun deleteAll(): Unit = implementation.deleteAll()

    // OLD
    open fun getKeyId(alias: String): String? = implementation.getKeyId(alias)

    companion object : ServiceProvider {
        override fun getService() = object : KeyStoreServiceUmu() {}
        override fun defaultImplementation() = defaultSoreServiceUmu()
    }
}



