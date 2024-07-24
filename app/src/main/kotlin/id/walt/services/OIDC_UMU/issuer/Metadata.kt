package id.walt.services.OIDC_UMU.issuer

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import id.walt.services.OIDC_UMU.generarValorAleatorio
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.*
import kotlinx.serialization.json.*


data class Metadata(
    val issuer: String,
    val authorizationEndpoint: List<String>,
    val tokenEndpoint: String,
    val scopesSupported: List<String>,
    val responseTypesSupported: List<String>,
    val responseModesSupported: List<String>,
    val grantTypesSupported: List<String>,
    val subjectTypesSupported: List<String>,
    val idTokenSigningAlgValuesSupported: List<String>,
    val requestObjectSigningAlgValuesSupported: List<String>,
    val requestParameterSupported: Boolean,
    val tokenEndpointAuthMethodsSupported: List<String>,
    val requestUriParameterSupported: Boolean,
    val requestAuthenticationMethods: JsonObject,
    val vpFormatsSupported: JsonObject,
    val subjectSyntaxTypesSupported: List<String>,
    val subjectSyntaxTypesDiscriminations: List<String>,
    val subjectTrustFrameworksSupported: List<String>,
    val idTokenTypesSupported: List<String>,
    val credentialIssuer: String?,
    val credentialEndpoint: String?,
    val authorizationServers: String?,
    val credentialConfigurations: Map<String, CredentialConfiguration>,
    val codeChallengeMethodSupported: List<String>
) {
    override fun toString(): String {
        return "Metadata(\n" +
                "issuer='$issuer',\n" +
                "authorizationEndpoint='$authorizationEndpoint',\n" +
                "tokenEndpoint='$tokenEndpoint',\n" +
                "scopesSupported=$scopesSupported,\n" +
                "responseTypesSupported=$responseTypesSupported,\n" +
                "responseModesSupported=$responseModesSupported,\n" +
                "grantTypesSupported=$grantTypesSupported,\n" +
                "subjectTypesSupported=$subjectTypesSupported,\n" +
                "idTokenSigningAlgValuesSupported=$idTokenSigningAlgValuesSupported,\n" +
                "requestObjectSigningAlgValuesSupported=$requestObjectSigningAlgValuesSupported,\n" +
                "requestParameterSupported=$requestParameterSupported,\n" +
                "tokenEndpointAuthMethodsSupported=$tokenEndpointAuthMethodsSupported,\n" +
                "requestUriParameterSupported=$requestUriParameterSupported,\n" +
                "requestAuthenticationMethods=$requestAuthenticationMethods,\n" +
                "vpFormatsSupported=$vpFormatsSupported,\n" +
                "subjectSyntaxTypesSupported=$subjectSyntaxTypesSupported,\n" +
                "subjectSyntaxTypesDiscriminations=$subjectSyntaxTypesDiscriminations,\n" +
                "subjectTrustFrameworksSupported=$subjectTrustFrameworksSupported,\n" +
                "idTokenTypesSupported=$idTokenTypesSupported,\n" +
                "credentialIssuer=$credentialIssuer,\n" +
                "credentialEndpoint=$credentialEndpoint,\n" +
                "authorizationServers=$authorizationServers,\n" +
                "credentialConfigurations=$credentialConfigurations\n" +
                "codeChallengeMethodSupported=$codeChallengeMethodSupported\n" +
                ")"
    }
}



fun generateMetadataJson(metadata: Metadata): String {
    val json = buildJsonObject {
        put("issuer", metadata.issuer)

        putJsonArray("authorizationEndpoint") {
            metadata.authorizationEndpoint.forEach { add(it) }
        }

        put("tokenEndpoint", metadata.tokenEndpoint)
        putJsonArray("scopesSupported") {
            metadata.scopesSupported.forEach { add(it) }
        }
        putJsonArray("responseTypesSupported") {
            metadata.responseTypesSupported.forEach { add(it) }
        }
        putJsonArray("responseModesSupported") {
            metadata.responseModesSupported.forEach { add(it) }
        }
        putJsonArray("grantTypesSupported") {
            metadata.grantTypesSupported.forEach { add(it) }
        }
        putJsonArray("subjectTypesSupported") {
            metadata.subjectTypesSupported.forEach { add(it) }
        }
        putJsonArray("idTokenSigningAlgValuesSupported") {
            metadata.idTokenSigningAlgValuesSupported.forEach { add(it) }
        }
        putJsonArray("requestObjectSigningAlgValuesSupported") {
            metadata.requestObjectSigningAlgValuesSupported.forEach { add(it) }
        }
        put("requestParameterSupported", metadata.requestParameterSupported)
        putJsonArray("tokenEndpointAuthMethodsSupported") {
            metadata.tokenEndpointAuthMethodsSupported.forEach { add(it) }
        }
        put("requestUriParameterSupported", metadata.requestUriParameterSupported)
        put("requestAuthenticationMethods", metadata.requestAuthenticationMethods.toString())
        put("vpFormatsSupported", metadata.vpFormatsSupported.toString())
        putJsonArray("subjectSyntaxTypesSupported") {
            metadata.subjectSyntaxTypesSupported.forEach { add(it) }
        }
        putJsonArray("subjectSyntaxTypesDiscriminations") {
            metadata.subjectSyntaxTypesDiscriminations.forEach { add(it) }
        }
        putJsonArray("subjectTrustFrameworksSupported") {
            metadata.subjectTrustFrameworksSupported.forEach { add(it) }
        }
        putJsonArray("idTokenTypesSupported") {
            metadata.idTokenTypesSupported.forEach { add(it) }
        }
        put("credentialIssuer", metadata.credentialIssuer)
        put("credentialEndpoint", metadata.credentialEndpoint)
        put("authorizationServers", metadata.authorizationServers)
        putJsonObject("credentialConfigurations") {
            metadata.credentialConfigurations.forEach { (key, value) ->
                putJsonObject(key) {
                    put("scope", value.scope)
                    put("format", value.format)
                }
            }
        }
        putJsonArray("codeChallengeMethodSupported") {
            metadata.codeChallengeMethodSupported.forEach { add(it) }
        }
    }
    return json.toString()
}


data class CredentialConfiguration(
    val format: String,
    val scope: String
)

// Función que realiza solicitudes GET y retorna Metadata
suspend fun fetchMetadataRequest(client: HttpClient, url: String): Metadata {
    val responseMetadata = client.get(url + "/.well-known/openid-credential-issuer")
    val metadata = parseMetadata(responseMetadata.bodyAsText())
    val responseAuthMetadata = client.get(url + "/.well-known/oauth-authorization-server")
    val authMetadata = parseAuthMetadata(responseAuthMetadata.bodyAsText())
    return metadata.copy(
        issuer = authMetadata.issuer,
        authorizationEndpoint = authMetadata.authorizationEndpoint,
        tokenEndpoint = authMetadata.tokenEndpoint,
        scopesSupported = authMetadata.scopesSupported,
        responseTypesSupported = authMetadata.responseTypesSupported,
        responseModesSupported = authMetadata.responseModesSupported,
        grantTypesSupported = authMetadata.grantTypesSupported,
        subjectTypesSupported = authMetadata.subjectTypesSupported,
        idTokenSigningAlgValuesSupported = authMetadata.idTokenSigningAlgValuesSupported,
        requestObjectSigningAlgValuesSupported = authMetadata.requestObjectSigningAlgValuesSupported,
        requestParameterSupported = authMetadata.requestParameterSupported,
        tokenEndpointAuthMethodsSupported = authMetadata.tokenEndpointAuthMethodsSupported,
        requestUriParameterSupported = authMetadata.requestUriParameterSupported,
        requestAuthenticationMethods = authMetadata.requestAuthenticationMethods,
        vpFormatsSupported = authMetadata.vpFormatsSupported,
        subjectSyntaxTypesSupported = authMetadata.subjectSyntaxTypesSupported,
        subjectSyntaxTypesDiscriminations = authMetadata.subjectSyntaxTypesDiscriminations,
        subjectTrustFrameworksSupported = authMetadata.subjectTrustFrameworksSupported,
        idTokenTypesSupported = authMetadata.idTokenTypesSupported,
        codeChallengeMethodSupported = authMetadata.codeChallengeMethodSupported
    )
}




fun parseAuthMetadata(jsonString: String): Metadata {
    val jsonObject = JsonParser.parseString(jsonString).asJsonObject
    return Metadata(
        issuer = jsonObject.get("issuer").asString,
        authorizationEndpoint = jsonObject.getAsJsonArray("authorization_endpoint").map { it.asString },
        tokenEndpoint = jsonObject.get("token_endpoint").asString,
        scopesSupported = jsonObject.getAsJsonArray("scopes_supported").map { it.asString },
        responseTypesSupported = jsonObject.getAsJsonArray("response_types_supported").map { it.asString },
        responseModesSupported = jsonObject.getAsJsonArray("response_modes_supported").map { it.asString },
        grantTypesSupported = jsonObject.getAsJsonArray("grant_types_supported").map { it.asString },
        subjectTypesSupported = jsonObject.getAsJsonArray("subject_types_supported").map { it.asString },
        idTokenSigningAlgValuesSupported = jsonObject.getAsJsonArray("id_token_signing_alg_values_supported").map { it.asString },
        requestObjectSigningAlgValuesSupported = jsonObject.getAsJsonArray("request_object_signing_alg_values_supported").map { it.asString },
        requestParameterSupported = jsonObject.get("request_parameter_supported").asBoolean,
        tokenEndpointAuthMethodsSupported = jsonObject.getAsJsonArray("token_endpoint_auth_methods_supported").map { it.asString },
        requestUriParameterSupported = jsonObject.get("request_uri_parameter_supported").asBoolean,
        requestAuthenticationMethods = jsonObject.getAsJsonObject("request_authentication_methods_supported"),
        vpFormatsSupported = jsonObject.getAsJsonObject("vp_formats_supported"),
        subjectSyntaxTypesSupported = jsonObject.getAsJsonArray("subject_syntax_types_supported").map { it.asString },
        subjectSyntaxTypesDiscriminations = jsonObject.getAsJsonArray("subject_syntax_types_discriminations").map { it.asString },
        subjectTrustFrameworksSupported = jsonObject.getAsJsonArray("subject_trust_frameworks_supported").map { it.asString },
        idTokenTypesSupported = jsonObject.getAsJsonArray("id_token_types_supported").map { it.asString },
        credentialIssuer = null,
        credentialEndpoint = null,
        authorizationServers = null,
        credentialConfigurations = emptyMap(),
        codeChallengeMethodSupported = jsonObject.getAsJsonArray("code_challenge_methods_supported").map { it.asString }
    )
}

fun parseMetadata(jsonString: String): Metadata {
    val jsonObject = JsonParser.parseString(jsonString).asJsonObject
    return Metadata(
        issuer = "",
        authorizationEndpoint = emptyList(),
        tokenEndpoint = "",
        scopesSupported = emptyList(),
        responseTypesSupported = emptyList(),
        responseModesSupported = emptyList(),
        grantTypesSupported = emptyList(),
        subjectTypesSupported = emptyList(),
        codeChallengeMethodSupported = emptyList(),
        idTokenSigningAlgValuesSupported = emptyList(),
        requestObjectSigningAlgValuesSupported = emptyList(),
        requestParameterSupported = false,
        tokenEndpointAuthMethodsSupported = emptyList(),
        requestUriParameterSupported = false,
        requestAuthenticationMethods = JsonObject(),
        vpFormatsSupported = JsonObject(),
        subjectSyntaxTypesSupported = emptyList(),
        subjectSyntaxTypesDiscriminations = emptyList(),
        subjectTrustFrameworksSupported = emptyList(),
        idTokenTypesSupported = emptyList(),
        credentialIssuer = jsonObject.get("credential_issuer")?.asString,
        credentialEndpoint = jsonObject.get("credential_endpoint")?.asString,
        authorizationServers = jsonObject.get("authorization_servers")?.asString,
        credentialConfigurations = jsonObject.getAsJsonObject("credential_configurations_supported").entrySet().associate {
            it.key to CredentialConfiguration(
                format = it.value.asJsonObject.get("format").asString,
                scope = it.value.asJsonObject.get("scope").asString
            )
        }
    )
}

fun checkValidMetadata(metadata: Metadata): Boolean {
    var isLdpVsFormatPresent = false
    var isAuthorizationCodeGrantPresent = false
    var isEdDSASigningAlgPresent = false
    var isS256CodeChallengeMethodPresent = false

    for ((key, configuration) in metadata.credentialConfigurations) {
        if (configuration.format == "ldp_vc") {
            isLdpVsFormatPresent = true
        }
    }

    if ("authorization_code" in metadata.grantTypesSupported) {
        isAuthorizationCodeGrantPresent = true
    }

    if ("EdDSA" in metadata.requestObjectSigningAlgValuesSupported) {
        isEdDSASigningAlgPresent = true
    }

    if ("S256" in metadata.codeChallengeMethodSupported) {
        isS256CodeChallengeMethodPresent = true
    }


    return isLdpVsFormatPresent && isAuthorizationCodeGrantPresent && isEdDSASigningAlgPresent && isS256CodeChallengeMethodPresent
}


    fun generateMetadata(ISSUER_PORT: Int, credentialTypes: Array<String>): String {
    val credentialIssuer = "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/"
    val credentialEndpoint = "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/credential"
    val authorizationServers = "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/auth"

    val credentialsConfigurations = credentialTypes.joinToString(separator = ",\n\t\t") { credentialType ->
        val scope = if (credentialType.endsWith("Credential")) {
            credentialType.removeSuffix("Credential")
        } else {
            credentialType
        }
        """
            "$credentialType": {
                "format": "ldp_vc",
                "scope": "$scope"
            }
            """.trimIndent()
    }

    return """
                {
                    "credential_issuer": "$credentialIssuer",
                    "credential_endpoint": "$credentialEndpoint",
                    "authorization_servers": "$authorizationServers",
                    "credential_configurations_supported": {
                        $credentialsConfigurations
                    }
                }
                """.trimIndent()
}

fun generateAuthMetadata(ISSUER_PORT: Int): String {

    return """
            { 
             "issuer":"https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer", 
             "authorization_endpoint": ["https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/auth", "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/auth-late","https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/auth-ePassport" ,"https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/code", "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/code-late", "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/code-ePassport"], 
             "token_endpoint":"https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/token", 
             "scopes_supported":["openid"], 
             "response_types_supported":["vp_token","id_token","code","token"], 
             "response_modes_supported":["query"], 
             "grant_types_supported":["authorization_code"], 
             "subject_types_supported":["public"], 
             "id_token_signing_alg_values_supported":["EdDSA","ES256"], 
             "request_object_signing_alg_values_supported":["EdDSA","ES256"], 
             "request_parameter_supported":true, 
             "token_endpoint_auth_methods_supported":["private_key_jwt"], 
             "request_uri_parameter_supported":true, 
             "request_authentication_methods_supported":{"authorization_endpoint":["request_object"]}, 
             "vp_formats_supported":{"jwt_vp":{"alg":["EdDSA","ES256"]}, 
             "jwt_vc":{"alg":["EdDSA","ES256"]}}, 
             "subject_syntax_types_supported":["did:key","did:ebsi"], 
             "subject_syntax_types_discriminations":["did:key:jwk_jcs-pub","did:ebsi:v1"], 
             "subject_trust_frameworks_supported":["ebsi", "TANGO"], 
             "id_token_types_supported":["subject_signed_id_token","attester_signed_id_token"], 
             "code_challenge_methods_supported":["S256"]
            } 
        """.trimIndent()
}

fun generateCredentialOffer(ISSUER_PORT: Int, credentialTypes: Array<String>): String {
    val json = buildJsonObject {
        put("credential_issuer", "https://wallet.testing1.k8s-cluster.tango.rid-intrasoft.eu/issuer/")
        putJsonArray("credential_configuration_ids") {
            credentialTypes.forEach { add(it) }
        }
        putJsonObject("grants") {
            putJsonObject("authorization_code") {
                put("issuer_state", generarValorAleatorio())
            }
            putJsonObject("urn:ietf:params:oauth:grant-type:pre-authorized_code") {
                put("pre-authorized_code", "0000000000")
            }
        }
    }
    return json.toString()
}

