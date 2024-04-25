package id.walt.services.storeUmu

import id.walt.common.SqlDbManager
import id.walt.crypto.*
import id.walt.services.context.ContextManager
import id.walt.services.keyUmu.KeyAlgorithmUmu
import id.walt.services.keystore.KeyStoreService
import inf.um.psmultisign.PSprivateKey
import inf.um.psmultisign.PSverfKey
import io.ktor.util.*
import mu.KotlinLogging
import java.sql.Connection
import java.sql.Statement
import kotlin.collections.ArrayList
import java.util.Base64;

class defaultSoreServiceUmu : KeyStoreServiceUmu() {

    private val log = KotlinLogging.logger {}


    init {
        SqlDbManager.start()
    }

    override fun deleteAll() {
        log.debug { "Deleting all keys from the database..." }

        SqlDbManager.getConnection().use { connection ->
            connection.apply {
                prepareStatement("DELETE FROM lt_key_umu").use { statement ->
                    when {
                        statement.executeUpdate() > 0 -> {
                            commit()
                            log.trace { "All keys deleted successfully." }
                        }
                        else -> {
                            log.error { "No keys found to delete. Rolling back transaction." }
                            rollback()
                        }
                    }
                }
            }
        }
        SqlDbManager.getConnection().use { connection ->
            connection.apply {
                prepareStatement("DELETE FROM lt_key_alias_umu").use { statement ->
                    when {
                        statement.executeUpdate() > 0 -> {
                            commit()
                            log.trace { "All alias deleted successfully." }
                        }
                        else -> {
                            log.error { "No alias found to delete. Rolling back transaction." }
                            rollback()
                        }
                    }
                }
            }
        }
    }


    override fun store(key: KeyUmu) {

        log.debug { "Saving key \"${key}\"..." }

        var privateK: String

        if (key.privateKey == null)
            privateK = ""
        else{
            privateK = key.privateKey.getEncoded().encodeBase64()
        }



        SqlDbManager.getConnection().use { connection ->
            connection.apply {
                prepareStatement(
                    "insert into lt_key_umu (name, pub, priv, algorithm) values (?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS
                ).use { statement ->
                    key.run {
                        listOf(
                            KeyIdUmu.id,
                            publicKey.getEncoded().encodeBase64(),
                            privateK,
                            algorithm.name,
                        ).forEachIndexed { index, str -> str?.let { statement.setString(index + 1, str) } }
                    }

                    when {
                        statement.executeUpdate() == UPDATE_SUCCESS -> {
                            commit()
                            log.trace { "Key \"${key}\" saved successfully." }
                        }

                        else -> {
                            log.error { "Error when saving key \"${key}\". Rolling back transaction." }
                            rollback()
                        }
                    }
                }
            }
        }
    }

    override fun load(alias: String): KeyUmu {
        log.debug { "Loading key \"${alias}\"..." }
        var key: KeyUmu? = null
        val keyId = getKeyId(alias) ?: alias
        SqlDbManager.getConnection().use { connection ->
            connection.prepareStatement("select * from lt_key_umu where name = ?").use { statement ->
                statement.setString(1, keyId)
                statement.executeQuery().use { result ->
                    if (result.next()) {

                        val private: PSprivateKey?
                        if (result.getString("priv") == ""){
                            private = null
                        }else {
                            private = PSprivateKey(Base64.getDecoder().decode(result.getString("priv")))

                        }

                        key = KeyUmu(
                            KeyIdUmu(keyId),
                            KeyAlgorithmUmu.valueOf(result.getString("algorithm")),
                            private,
                            PSverfKey(Base64.getDecoder().decode(result.getString("pub")))
                        )

                    }
                }
                connection.commit()
            }
        }
        return key ?: throw IllegalArgumentException("Could not load key: $keyId")
    }


    override fun getKeyId(alias: String): String? {
        log.trace { "Loading keyId for alias \"${alias}\"..." }

        SqlDbManager.getConnection().use { con ->
            con.prepareStatement("select k.name from lt_key_umu k, lt_key_alias_umu a where k.id = a.key_id and a.alias = ?")
                .use { statement ->
                    statement.setString(1, alias)

                    statement.executeQuery().use { rs ->
                        if (rs.next()) {
                            val id = rs.getString("name")
                            log.trace { "keyId \"${id}\" loaded." }
                            con.commit()
                            return id
                        }
                    }
                }
        }
        return null
    }

    override fun addAlias(keyId: KeyIdUmu, alias: String) {
        log.debug { "Adding alias \"${alias}\" for keyId \"${KeyId}\"..." }

        SqlDbManager.getConnection().use { con ->

            con.prepareStatement("select k.id from lt_key_umu k where k.name = ?").use { statement ->
                statement.setString(1, keyId.id)

                statement.executeQuery().use { rs ->
                    if (rs.next()) {
                        rs.getInt("id").let { keyId ->
                            con.prepareStatement("insert into lt_key_alias_umu (key_id, alias) values (?, ?)")
                                .use { stmt ->
                                    stmt.setInt(1, keyId)
                                    stmt.setString(2, alias)
                                    stmt.executeUpdate()
                                    log.trace { "Alias \"${alias}\" for keyId \"${keyId}\" saved successfully." }
                                }
                        }
                    }
                }
            }
            con.commit()
        }
    }

    override fun listKeys(): List<KeyUmu> {
        val keys = ArrayList<KeyUmu>()
        SqlDbManager.getConnection().use { con ->
            con.prepareStatement("select * from lt_key_umu").use { stmt ->
                stmt.executeQuery().use { rs ->
                    while (rs.next()) {
                        val private: PSprivateKey?
                        if (rs.getString("priv") == ""){
                            private = null
                        }else {
                            private = PSprivateKey(Base64.getDecoder().decode(rs.getString("priv")))

                        }
                        keys.add(
                            KeyUmu(
                                KeyIdUmu(rs.getString("name")),
                                KeyAlgorithmUmu.valueOf(rs.getString("algorithm")),
                                private,
                                PSverfKey(Base64.getDecoder().decode(rs.getString("pub")))
                            )

                        )
                    }
                }
            }
            con.commit()
        }
        return keys
    }

    private fun deleteKeyAndAliases(keyName: String, con: Connection) {
        con.prepareStatement("select id from lt_key_umu where name = ?").use { stmt ->
            stmt.setString(1, keyName)
            stmt.executeQuery().use { rs ->
                while (rs.next()) {
                    con.prepareStatement("delete from lt_key_alias_umu where key_id = ?").use { stmt ->
                        stmt.setString(1, rs.getString("id"))
                        stmt.executeUpdate()
                    }
                }
            }
        }

        con.prepareStatement("delete from lt_key_umu where name = ?")
            .use { stmt ->
                stmt.setString(1, keyName)
                stmt.executeUpdate()
            }
    }

    private fun deleteKeyByAliases(alias: String, con: Connection) {
        con.prepareStatement("select key_id from lt_key_alias_umu where alias = ?").use { stmt ->
            stmt.setString(1, alias)
            stmt.executeQuery().use { rs ->
                while (rs.next()) {
                    con.prepareStatement("delete from lt_key_umu where id = ?").use { stmt ->
                        stmt.setString(1, rs.getString("key_id"))
                        stmt.executeUpdate()
                    }
                    con.prepareStatement("delete from lt_key_alias_umu where key_id = ?").use { stmt ->
                        stmt.setString(1, rs.getString("key_id"))
                        stmt.executeUpdate()
                    }
                }
            }
        }
    }

    override fun delete(alias: String) {
        log.debug { "Deleting key \"${alias}\"." }

        SqlDbManager.getConnection().use { con ->

            deleteKeyAndAliases(alias, con)

            deleteKeyByAliases(alias, con)

            con.commit()
        }
    }

    companion object {
        private const val UPDATE_SUCCESS = 1
    }

}

