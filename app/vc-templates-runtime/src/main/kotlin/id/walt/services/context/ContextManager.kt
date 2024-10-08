package id.walt.services.context

import id.walt.servicematrix.BaseService
import id.walt.servicematrix.ServiceRegistry
import id.walt.services.hkvstore.HKVStoreService
import id.walt.services.keystore.KeyStoreService
import id.walt.services.storeUmu.KeyStoreServiceUmu
import id.walt.services.vcstore.VcStoreService

interface Context {
    val keyStore: KeyStoreService
    val vcStore: VcStoreService
    val hkvStore: HKVStoreService
    val keyStoreUmu: KeyStoreServiceUmu
}

abstract class ContextManager : BaseService() {
    override val implementation: ContextManager get() = serviceImplementation()

    abstract val keyStore: KeyStoreService
    abstract val vcStore: VcStoreService
    abstract val hkvStore: HKVStoreService

    abstract val keyStoreUmu: KeyStoreServiceUmu



    abstract fun <R> runWith(context: Context, action: () -> R): R

    companion object {
        val implementation: ContextManager get() = ServiceRegistry.getService()

        fun getService() = implementation

        // convenience accessors
        val keyStore: KeyStoreService
            get() = implementation.keyStore
        val vcStore: VcStoreService
            get() = implementation.vcStore
        val hkvStore: HKVStoreService
            get() = implementation.hkvStore


        val keyStoreUmu: KeyStoreServiceUmu
            get() = implementation.keyStoreUmu


        fun <R> runWith(context: Context, action: () -> R): R = implementation.runWith(context, action)
    }
}

open class WaltIdContextManager : ContextManager() {

    val threadContexts: HashMap<String, Context> = HashMap()
    private fun getCurrentThreadId(): String = Thread.currentThread().run { name + id }

    val currentContext
        get() = threadContexts[getCurrentThreadId()] ?: WaltIdContext

    fun setCurrentContext(context: Context) {
        threadContexts[getCurrentThreadId()] = context
    }

    fun resetCurrentContext() {
        threadContexts.remove(getCurrentThreadId())
    }

    override fun <R> runWith(context: Context, action: () -> R): R {
        try {
            setCurrentContext(context)
            return action.invoke()
        } finally {
            resetCurrentContext()
        }
    }

    override val keyStore: KeyStoreService
        get() = currentContext.keyStore
    override val vcStore: VcStoreService
        get() = currentContext.vcStore
    override val hkvStore: HKVStoreService
        get() = currentContext.hkvStore


    override val keyStoreUmu: KeyStoreServiceUmu
        get() = currentContext.keyStoreUmu



}
