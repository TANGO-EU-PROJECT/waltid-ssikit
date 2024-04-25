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
import id.walt.services.keystore.KeyType
import id.walt.services.ecosystems.fabric.VDR
import java.nio.file.Path 
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.file
import java.io.File


class FabricComand : CliktCommand(
    name="fabric", help="""
    
    Carries out communication with hyperledger fabric for registration and DID request.

    """
){

    override fun run() {
    
    }
}


//Upload DID docuemnts.
class CreateComand : CliktCommand(
    name="create", help="""
    
    Create create new DID Document.

    """
){
    val key: String by option("-k", "--key", help = "KEY to be onboarded").required()
    val didPath: String by option("-d", "--did", help = "Path to the DID document").required()

    override fun run() {
        val file = File(didPath)
        

        if (file.exists()) {
            val doc = file.readText()
            echo("Uploading new DID documents...")
            println("\n--> Submit Transaction: Set, key: $key, value: $doc")
            VDR.setValue(key,doc)  
        } else {
            echo("The file path is wrong...")
        }
  
    }
}

//Get DID docuemnts.
class resolveCommand : CliktCommand(
    name="resolve", help="""
    
    makes DID resolution via FABRIC.

    """
){
    val key: String by option("-k", "--key", help = "KEY to be onboarded").required()
    override fun run() {
        echo("Sending a did resolution to the hyperledger fabric blockchain...")
        println("\n--> Evaluate Transaction: Get, key: $key")
        val result = VDR.getValue(key)    
        if (result != null) println("Result: $result")
        else println("Did not found")
    }
}

