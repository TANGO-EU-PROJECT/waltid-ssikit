package id.walt.services.OIDC_UMU.wallet

import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.custodian.Custodian
import java.io.File

// Salida mas legible
val verde = "\u001B[32m"
val rojo = "\u001B[31m"
val reset = "\u001B[0m"

fun deleteFile(name: String): Boolean {
    val filePath = "./data/credential-store/custodian/"+name+".cred"
    val file = File(filePath)
    if (file.exists()) {
        file.delete()
        return true
    } else {
        return false
    }
}

fun saveCredential(credential:String, name:String) {
    println("\n$verde[+] Wallet: Save credential $reset\n")
    val cred = credential.toVerifiableCredential()
    Custodian.getService().storeCredential(name, cred)
}


// Lista el conjunto de credenciales almacenadas

fun listCredential(): String{

    println("\n$verde[+] Wallet: List credential $reset\n")

    var creds = "{"
    val verifiableCreds = Custodian.getService().listCredentials()
    verifiableCreds.forEachIndexed { index, vc ->
        creds += "\"${index + 1}\": [ $vc ]"
        if (index < verifiableCreds.size - 1) {
            creds += ","
        }
    }
    creds += "}"

    return creds
}
