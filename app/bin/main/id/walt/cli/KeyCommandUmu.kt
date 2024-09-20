package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.choice
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.path
import id.walt.common.readWhenContent
import id.walt.crypto.KeyAlgorithm
import id.walt.services.key.KeyFormat
import id.walt.services.key.KeyService
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.bitcoinj.core.Base58
import java.nio.file.Path

private val keyService = KeyServiceUmu.getService()
private val log = KotlinLogging.logger {}
class KeyCommandUmu: CliktCommand(
    name = "keyumu",
    help = """Key Management Umu

       Generation export/import, and deletion of asymmetric keys."""
) {
    val algorithm: String by option(help = "Key algorithm [PsmsBlsSignature2022]").default("PsmsBlsSignature2022")

    override fun run() {
    }
}

class ImportKeyCommandUmu : CliktCommand(
    name = "import", help = """Import key in base64 proto encoded

        """
) {

    val keyFile: Path by argument("file", help = "File containing the key").path()

    override fun run() {
        echo("Importing key from \"$keyFile\"...")

        val keyStr = readWhenContent(keyFile)

        val keyId = keyService.importKey(keyStr)

        echo("\nResults:\n")

        if (keyId != null) {
            echo("Key \"${keyId.id}\" imported.")
        }

    }
}

class ExportKeyCommandUmu : CliktCommand(
    name = "export", help = """Export keys

        Export key in base64 proto encoded format."""
) {

    val keyId: String by argument("KEY-ID", help = "Key ID or key alias")

    override fun run() {


        echo("Exporting PsmsBlsSignature2022 key \"$keyId\"...")
        val exportValue = keyService.export(keyId)

        echo("\nResults:\n")

        println(exportValue)
    }
}

class ListKeysCommandUmu : CliktCommand(
    name = "list", help = """List keys

        List all keys in the key store umu."""
) {

    override fun run() {

        echo("Listing keys ...")

        echo("\nResults:\n")

        keyService.listKeys().forEachIndexed { index, (keyId, algorithm, priv, pub) ->
            echo("- ${index + 1}: \"${keyId}\" (Algorithm: \"${algorithm.name}\", pubKey(base58): \"${Base58.encode((pub).getEncoded())}\" - privKey(base58): \"${priv}\")")
        }
    }
}

class DeleteKeyCommandUmu : CliktCommand(
    name = "delete", help = """Delete key

        Deletes the key with the specified ID.
        """
) {

    val keyId: String by argument("KEY-ID", help = "Key ID or key alias")

    override fun run() {
        echo("Deleting key \"$keyId\"...")

        keyService.delete(keyId)

        echo("\nResults:\n")

        echo("Key \"${keyId}\" deleted.")
    }
}

class DeleteKeyAllUmu : CliktCommand(
    name = "deleteAll", help = """Delete keys

        Deletes all keys.
        """
) {


    override fun run() {
        echo("Deleting all keys...")

        keyService.deleteAll()

        echo("Keys deleted.")
    }
}



