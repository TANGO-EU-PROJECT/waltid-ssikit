package id.walt.services.OIDC_UMU

import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*

// Genera un valor aleatorio (utilizando para la generación del challenge en el obtención del auth token)
fun generarValorAleatorio(): String {
    val secureRandom = SecureRandom()
    val bytes = ByteArray(32)
    secureRandom.nextBytes(bytes)

    val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    val random = base64String.substring(0, 16) + "-" + base64String.substring(16)

    return random
}

// Función para realizar el hash 256

fun String.sha256(): String {
    val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
    return bytes.joinToString("") { "%02x".format(it) }
}
// Obtiene un determinado valor (v) dentro de un JWT
fun getValueFromJWT(jwt: String, v: String): String {
    val parts = jwt.split(".")
    val payload = parts[1]
    val decodedPayload = String(Base64.getDecoder().decode(payload))
    val jsonElement = Json.parseToJsonElement(decodedPayload)
    val content = jsonElement.jsonObject[v]?.toString()?.removeSurrounding("\"") ?: throw IllegalArgumentException("Error processing the JWT.")
    return content
}

/*

    Verificación de las firmas de un JWT, tanto a nivel local como haciendo resolución de DIDs

*/
fun verifyJWT(jwt: String): Boolean
{
    val result = JwtService.getService().verify(jwt).verified
    return result
}

// Comprueba que el nonce se haya firmado correctamente
fun isProofValid(proof: String, nonce: String, fieldValue: String): Boolean {

    val iss =  getValueFromJWT(proof, "iss")
    DidService.importDidAndKeys(iss)
    val c_nonce = getValueFromJWT(proof, fieldValue)
    if (c_nonce != nonce) return false

    return verifyJWT(proof)
}

