package id.walt.services.OIDC_UMU.wallet

import com.google.gson.Gson
import com.google.gson.JsonParser
import com.nimbusds.oauth2.sdk.AuthorizationRequest
import id.walt.common.KlaxonWithConverters
import id.walt.credentials.w3c.toPresentableCredential
import id.walt.credentials.w3c.toVerifiablePresentation
import id.walt.model.dif.PresentationDefinition
import id.walt.services.OIDC_UMU.generarValorAleatorio
import id.walt.services.oidc.CompatibilityMode
import id.walt.services.oidc.OIDC4VPService
import id.walt.services.vc.JsonLdCredentialService
import io.ktor.client.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.URI

private val jsonLdCredentialService = JsonLdCredentialService.getService()
data class CredentialOffer(
    var credential_issuer: String,
    var issuerState: String,
    var preAuthorizedCode: String,
    var credentialConfigurationIds: List<String>
)




// Función que parsea el credentialOffer.json y extrae los valores específicos
fun parseCredentialOffer(jsonString: String): CredentialOffer {
    val jsonObject = JsonParser.parseString(jsonString).asJsonObject

    // Extraer 'credential_issuer'
    val credential_issuer = if (jsonObject.has("credential_issuer")) jsonObject.get("credential_issuer").asString else "No issuer provided"

    // Intenta extraer 'issuer_state' desde 'authorization_code'
    val issuerState = jsonObject.getAsJsonObject("grants")
        ?.getAsJsonObject("authorization_code")
        ?.get("issuer_state")?.asString ?: "No state provided"

    // Intenta extraer 'pre-authorized_code'
    val preAuthorizedCode = jsonObject.getAsJsonObject("grants")
        ?.getAsJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        ?.get("pre-authorized_code")?.asString ?: "No code provided"

    // Extraer 'credential_configuration_ids' como una lista de Strings
    val credentialConfigurationIds = jsonObject.getAsJsonArray("credential_configuration_ids")?.map { it.asString } ?: emptyList()

    return CredentialOffer(credential_issuer, issuerState, preAuthorizedCode, credentialConfigurationIds)
}



// Obtención de la política indicada por el verifier

fun extractPresentationDefinitionInfo(json: String):Triple<MutableList<String>, MutableList<String>, MutableList<String>>{
    val gson = Gson()
    val presentationDefinition = gson.fromJson(json, PresentationDefinition::class.java)
    val credentialTypes = mutableListOf<String>()
    val credentialSubjectAttributes = mutableListOf<String>()
    val paths = mutableListOf<String>()
    presentationDefinition.input_descriptors.forEach { descriptor ->
        descriptor.constraints?.fields?.forEach { field ->
            field.filter?.let { filter ->
                (filter["const"] as? String)?.let { constValue ->
                    credentialSubjectAttributes.add(constValue)
                }
                (filter["contains"] as? Map<*, *>)?.get("const")?.let { containsConstValue ->
                    if (containsConstValue is String) {
                        credentialTypes.add(containsConstValue)
                    }
                }
            }
            val pathString = field.path.joinToString(separator = ", ")
            if (pathString != "$.type") paths.add(pathString)
        }
    }


    return Triple(credentialTypes,paths ,credentialSubjectAttributes)
}




/*
    Al igual que la anterior función parsea el mensaje del verifier para obtener la política solicitada y
    devolver una seria de listas en formato String con la información relevante (tipos de credenciales, atributos
    y valores de esos atributos...)
*/

fun vpTokenDetails(last_vp_token: String): String {

    val req = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(last_vp_token))
    if (req == null){
        println("Error parsing SIOP request")
        return """{"error": "Error parsing SIOP request"}"""
    }
    val definition = OIDC4VPService.getPresentationDefinition(req)
    val gson = Gson()
    val presentationDefinition = gson.fromJson(KlaxonWithConverters().toJsonString(definition), PresentationDefinition::class.java)
    val credentialTypes = mutableListOf<String>()
    val credentialSubjectAttributes = mutableListOf<String>()
    val paths = mutableListOf<String>()
    presentationDefinition.input_descriptors.forEach { descriptor ->
        descriptor.constraints?.fields?.forEach { field ->
            field.filter?.let { filter ->
                (filter["const"] as? String)?.let { constValue ->
                    credentialSubjectAttributes.add(constValue)
                }
                (filter["contains"] as? Map<*, *>)?.get("const")?.let { containsConstValue ->
                    if (containsConstValue is String) {
                        credentialTypes.add(containsConstValue)
                    }
                }
            }
            val pathString = field.path.joinToString(separator = ", ")
            if (pathString != "$.type") paths.add(pathString)
        }
    }

    return credentialTypes.toString()+paths.toString()+credentialSubjectAttributes.toString()

}

// Generación de la verifiable presentation

fun createVerifiablePresentation(credential: String, did: String): String {
    try {


        val presentableCredentials = listOf(credential.toPresentableCredential())

        val presentation = jsonLdCredentialService.present(
            vcs = presentableCredentials,
            holderDid = did,
            domain = null,
            challenge = null,
            expirationDate = null
        )

        return presentation
    } catch (e: Exception) {
        e.printStackTrace()
        return "Error creating the verifiable presentation: ${e.message}"
    }


}

// Genera de forma dinámica un frame para realizar la derivación

fun generarFrame(credentialType: MutableList<String>, atributos: MutableList<String>): String {
    val contextos = listOf(
        "\"https://www.w3.org/2018/credentials/v1\"",
        "\"https://w3id.org/citizenship/v1\"",
        "\"https://ssiproject.inf.um.es/security/psms/v1\""
    )

    val tipos = mutableListOf("\"VerifiableCredential\"")
    tipos.addAll(credentialType.map { "\"$it\"" })

    val atributosCredencial = atributos.map {
        it.replace("$.credentialSubject.", "") to "{}"
    }.toMap()

    val tipoCredencial = if (credentialType.contains("PermanentResidentCard")) "\"PermanentResident\"" else "\"\""

    val json = """
                {
                  "@context": [${contextos.joinToString(", ")}],
                  "@type": [${tipos.joinToString(", ")}],
                  "credentialSubject": {
                    "@type": $tipoCredencial,
                    "@explicit": true,
                    ${atributosCredencial.map { "\"${it.key}\": ${it.value}" }.joinToString(",\n        ")}
                  }
                }
                """.trimIndent()

    return json
}

// Recibe la credenciales seleccionada, generada la VP y se comunica con el issuer para recibir el JWT necesario.

suspend fun VerfiablePresentation(client: HttpClient, credential: String, did: String, keyAlias: String, last_authorization_request: AuthorizationRequest?,endpoint_verify_vp: String): String {

    println("\n$verde[+] Wallet: Creating a VP $reset\n")
    val presentation = createVerifiablePresentation(credential, did).toVerifiablePresentation()
    if (last_authorization_request == null) return "ERROR"
    val resp = OIDC4VPService.getSIOPResponseFor(last_authorization_request, did, listOf(presentation),keyAlias)
    val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
    val result = OIDC4VPService.postSIOPResponse_UMU(last_authorization_request, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo", URI.create(endpoint_verify_vp))
    return result
}

suspend fun DeriveCredential(client: HttpClient, credential: String, did: String, last_authorization_request: AuthorizationRequest?, keyAlias: String, endpoint_verify_vp: String): String {


    val presentationDefinition = OIDC4VPService.getPresentationDefinition(last_authorization_request!!)
    val (credentialTypes,paths ,credentialSubjectAttributes) = extractPresentationDefinitionInfo(KlaxonWithConverters().toJsonString(presentationDefinition))

    val frame = generarFrame(credentialTypes,paths)

    //val frame = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://w3id.org/citizenship/v1\",\"https://ssiproject.inf.um.es/security/psms/v1\"],\"@type\":[\"VerifiableCredential\",\"PermanentResidentCard\"],\"credentialSubject\":{\"@type\":\"PermanentResident\",\"@explicit\":true,\"givenName\":{},\"gender\":{}}}"

    val nonce = generarValorAleatorio()

    val jsonString = credential.trimIndent()
    val jsonElement = Json.parseToJsonElement(jsonString)
    val issuer = jsonElement.jsonObject["issuer"]?.toString()?.replace("\"", "")

    if (issuer != null){
        val deriveVC = jsonLdCredentialService.deriveVC(credential, issuer = issuer, challenge = nonce, frame = frame, domain = null, expirationDate = null);

        val presentation = createVerifiablePresentation(deriveVC, did).toVerifiablePresentation()
        if (last_authorization_request == null) return "ERROR"
        val resp = OIDC4VPService.getSIOPResponseFor(last_authorization_request, did, listOf(presentation),keyAlias)
        val url2 = "http://oidc4vp-proxy:8080"+"/ngsi-ld/v1/entities/urn:a.*"
        val result = OIDC4VPService.postSIOPResponse_UMU(last_authorization_request, resp, CompatibilityMode.OIDC, "GET", url2, "requester de ejemplo",URI.create(endpoint_verify_vp))

        return result
    }
    else
    {
        throw Exception("It has not been possible to obtain the credential issuer")
    }
}

fun obtainAuthorizationEndpoint(clientId: String, authorizationEndpoints: List<String>): String? {

    // Verificar si lateAuth es true
    if (clientId == "") {
        for (uri in authorizationEndpoints) {
            if ("late" in uri && "auth" in uri) {
                return uri
            }
        }
    }


    val authRegex = Regex("/auth$")
    for (uri in authorizationEndpoints) {
        if (authRegex.containsMatchIn(uri)) {
            return uri
        }
    }

    // Si no se encuentra ninguna coincidencia, se puede devolver null
    return null
}

fun obtainAuthorizationEndpoint_ePassport(authorizationEndpoints: List<String>): String? {

    for (uri in authorizationEndpoints) {

        if ("ePassport" in uri && "auth" in uri) {
            return uri
        }
    }
    return null
}
