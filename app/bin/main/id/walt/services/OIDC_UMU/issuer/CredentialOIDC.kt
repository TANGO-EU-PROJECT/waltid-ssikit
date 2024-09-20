package id.walt.services.OIDC_UMU.issuer

import com.google.gson.Gson
import com.google.gson.JsonObject
import id.walt.cli.IssuerCommand
import id.walt.crypto.LdSignatureType
import id.walt.model.credential.status.CredentialStatus
import id.walt.sdjwt.DecoyMode
import id.walt.sdjwt.SDMap
import id.walt.services.OIDC_UMU.getValueFromJWT
import id.walt.services.OIDC_UMU.isProofValid
import id.walt.services.OIDC_UMU.verifyJWT
import id.walt.services.OIDC_UMU.wallet.reset
import id.walt.services.OIDC_UMU.wallet.rojo
import id.walt.services.OIDC_UMU.wallet.verde
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import id.walt.services.jwt.WaltIdJwtService
import id.walt.signatory.Ecosystem
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import mu.KotlinLogging
import java.nio.file.Files
import java.nio.file.Paths
import java.time.Instant
import java.util.*

class CredentialOIDC (
    private val DID_BACKEND: String,
    private val KEY_ALIAS: String,
) {

    private val ISSUER_PORT = System.getenv("ISSUER_PORT").toInt()
    val log = KotlinLogging.logger {}
    val jwtService = WaltIdJwtService()
    suspend fun credential(
        call: ApplicationCall,
        tokenRegistry : MutableMap<String, IssuerCommand.TokenInfo>,
        authRequestRegistry: MutableMap<String, IssuerCommand.AuthRequest>
    ) {

        println("\n$verde[+] Issuer: Get credential from issuer.$reset\n")

        try{

            val parameters = call.receiveParameters()
            val proof = parameters["proof"]?: ""
            val authorizationHeader = call.request.headers["Authorization"]?: ""
            val authorization = authorizationHeader.substringAfter("Bearer ", "")


            val clientId = getValueFromJWT(authorization, "client_id")
            val subjectDid = getValueFromJWT(proof, "iss")

            if (tokenRegistry[clientId] == null) throw IllegalArgumentException("The clientId isn't valid.")

            // Comprueba que el access token sea válido (cabecera de autenticación)
            if (!isAccessTokenValid(authorization, tokenRegistry)) throw IllegalArgumentException("The authorization header isn't valid.")
            // Comprueba que el nonce este firmado correctamente

            if (!isProofValid(proof,tokenRegistry[clientId]!!.nonce,"c_nonce")) throw IllegalArgumentException("The proof isn't valid.")  // TODO : la verificación de la firma solo funciona de manera local
            val authRequestInfo = authRequestRegistry[clientId] ?: throw IllegalArgumentException("The clientId isn't valid.")

            val templateFilePath = "./src/main/resources/vc-templates/"+authRequestInfo.credentialtype+"-template.json"
            val jsonTemplate = Files.readString(Paths.get(templateFilePath))

            val gson = Gson()
            val credential_empty = gson.fromJson(jsonTemplate, JsonObject::class.java)
            val credentialSubject = credential_empty.getAsJsonObject("credentialSubject")


            authRequestInfo.credentialSubject.forEach { (key, value) ->
                credentialSubject.addProperty(key, value.toString())
            }

            val credential = gson.toJson(credential_empty)

            // Obtención de la credencial firmada


            val credential_signed = CreateCredential(DID_BACKEND ,subjectDid, credential, null, ProofType.LD_PROOF, "assertionMethod", LdSignatureType.PsmsBlsSignature2022, Ecosystem.DEFAULT , null, DecoyMode.NONE, 0, null)


            log.debug { "Credential -> [!] Issuer logs: credential_signed - ${credential_signed}" }.toString()

            call.respond(credential_signed)


        } catch (e: IllegalArgumentException) {
            println(rojo + "[!] Error: ${e.message}" + reset)
            call.respond(HttpStatusCode.BadRequest, mapOf("error" to e.message))
        } catch (e: Exception) {
            println(rojo + "[!] Unexpected Error: ${e.localizedMessage}" + reset)
            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "An unexpected error occurred."))
        }
    }






    // Comprueba la validez de un accesstoken (firma y tiempo de expiración)
    fun isAccessTokenValid(jwt: String, tokenRegistry: MutableMap<String, IssuerCommand.TokenInfo>): Boolean {


        val parts = jwt.split(".")
        if (parts.size != 3) return false

        val payload = parts[1]
        val decodedPayload = String(Base64.getDecoder().decode(payload))
        val jsonElement = Json.parseToJsonElement(decodedPayload)
        if (!jsonElement.jsonObject.containsKey("iss") ||
            !jsonElement.jsonObject.containsKey("exp") ||
            !jsonElement.jsonObject.containsKey("client_id")) return false

        val clientId = jsonElement.jsonObject["client_id"]?.toString()?.removeSurrounding("\"") ?: return false
        val exp = jsonElement.jsonObject["exp"]?.toString()?.removeSurrounding("\"") ?: return false
        val tokenInfo = tokenRegistry[clientId] ?: return false
        if (tokenInfo.bearer != jwt) return false
        if (!verifyJWT(jwt)) return false
        val currentTime = Instant.now()
        if (tokenInfo.expirationTime.isBefore(currentTime)) return false
        return true
    }


    // Crea una credencial firmada con el DID del issuer
    fun CreateCredential(issuerDid: String, subjectDid: String, template: String, issuerVerificationMethod: String?, proofType: ProofType, proofPurpose: String, ldSignatureType: LdSignatureType?, ecosystem: Ecosystem, statusType: CredentialStatus.Types?, decoyMode: DecoyMode, numDecoys: Int, selectiveDisclosurePaths: List<String>?): String {
        val signatory = Signatory.getService()
        val selectiveDisclosure = selectiveDisclosurePaths?.let { SDMap.generateSDMap(it, decoyMode, numDecoys) }
        val vcStr: String = runCatching {
            signatory.issue_umu(
                template, ProofConfig(
                    issuerDid = issuerDid,
                    subjectDid = subjectDid,
                    issuerVerificationMethod = issuerVerificationMethod,
                    proofType = proofType,
                    proofPurpose = proofPurpose,
                    ldSignatureType = ldSignatureType,
                    ecosystem = ecosystem,
                    statusType = statusType,
                    creator = issuerDid,
                    selectiveDisclosure = selectiveDisclosure
                )

            )
        }.getOrElse { err ->
            when (err) {
                is IllegalArgumentException -> log.error {  "Illegal argument: ${err.message}"}
                else -> log.error {  "Error: ${err.message}"}
            }
            return "Error creating the VC"
        }

        return vcStr
    }






}
