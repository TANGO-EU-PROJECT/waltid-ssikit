package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import java.net.URI
import id.walt.services.oidc.OIDC4CIService
import java.security.SecureRandom
import com.google.gson.Gson
import com.nimbusds.jwt.JWTClaimsSet
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import id.walt.model.oidc.*
import id.walt.services.key.KeyService
import java.util.*
import id.walt.services.keystore.KeyType
import id.walt.common.SqlDbManager
import java.net.URLEncoder
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import io.ktor.client.request.forms.*


import org.bitcoinj.core.Base58




/* SSIKIT Holder */
class Holder :
        CliktCommand(
                name = "holder",
                help =
                        """Ejemplo de conexión con Relaying party.
         """
        ) {

        // endpoints
        val ENDPOINT_LIST_CREDENTIALS = "https://localhost:8443/list"
        val ENDPOINT_AUTH = "https://localhost:8443/auth"
        val ENDPOINT_CODE = "https://localhost:8443/code"
        val ENDPOINT_TOKEN = "https://localhost:8443/token"
        val ENDPOINT_CREDENTIAL = "https://localhost:8443/credential"

        // Salida mas legible
        val verde = "\u001B[32m"
        val rojo = "\u001B[31m"
        val reset = "\u001B[0m"

        // DID
        val ISSUER_DID = "did:key:z6MkugRRy3cTidYmH7gr8f7HHdFZ4MKdQadQwKpCbcBthurW"

        // Servicios
        private val keyService = KeyService.getService()
        val keyID = "9994f5a040494123a5d9761d461d280d"

        /* 
        init {
            SqlDbManager.start()
        }
        */
    
        override fun run() = runBlocking {

            val client =
                    HttpClient() {
                        install(ContentNegotiation) { json() }
                        expectSuccess = false
                    }
                        
            
            val clientID = "123456"
            val clientSecret="abc"

            val credentialType = get_OIDC_discovery_document(client)

            val challenge = generarStateAleatorio()

            val auth_code = push_OIDC_auth_request(client, challenge)

            println("challenge: "+challenge)
            println("auth code: "+auth_code)

            val token = get_Access_Token(client, auth_code, challenge, clientID, clientSecret,"example.com")

            println(token)

            // Obtener la credencial

            val credential = getCredential(client, token, credentialType)    
            println(credential)   
            



            client.close()

        }

    suspend fun getCredential(client: HttpClient, token: String, credentialType: String): String {
        println("")
        println(verde+"[+] GET credential"+reset)
        println("")

        val gson = Gson()
        val jsonObject = gson.fromJson(token, Map::class.java)
        var access_token = jsonObject["access_token"] as String
        println("access token: "+access_token)
        var valor_nonce = jsonObject["c_nonce"] as String
        println("c_nonce: "+valor_nonce)
        val template = credentialType

         

        val nonce_signed = generateDidProof(ISSUER_DID,valor_nonce)
        //val key = getPublicKey(keyID)

        val response = client.get(ENDPOINT_CREDENTIAL) {
            url {
                parameters.append("nonce_signed", nonce_signed.toString())
                parameters.append("template", template)
                parameters.append("token", access_token)
                //parameters.append("publicKey", key)

            }
        }


        //println("public key: "+key)
        println("acces_token: "+access_token)
        println("nonce_signed: "+nonce_signed)
        println("nonce: "+valor_nonce)

        val credential: String = response.bodyAsText()
        return credential
    }

    suspend fun get_Access_Token(client: HttpClient, authCode: String, code: String, clientId: String, clientSecret: String, redirectUri: String): String {
        println("")
        println(verde+"[+] GET access Token"+reset)
        println("")
    
        // Codificar clientId y clientSecret para la autenticación básica
        val authHeaderValue = Base64.getEncoder().encodeToString("$clientId:$clientSecret".toByteArray(Charsets.UTF_8))
    
        val response = client.post(ENDPOINT_TOKEN) {
            // Configurar el encabezado de autorización
            header(HttpHeaders.Authorization, "Basic $authHeaderValue")
            header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
    
            // Configurar el cuerpo de la petición
            setBody(FormDataContent(Parameters.build {
                append("grant_type", "authorization_code")
                append("code", authCode)
                append("code_verifier", code.sha256())
                append("redirect_uri", redirectUri)
            }))
        }
    
        val token: String = response.bodyAsText()
        return token
    }

    suspend fun push_OIDC_auth_request(client: HttpClient, challenge: String): String {
        println("")
        println(verde + "[+] PUSH OIDC auth request" + reset)
        println("")
    
        // Preparar los parámetros de la solicitud
        val responseType = "code"
        val clientId = "123456"  
        val codeChallengeMethod = "S256"
        val redirectUri = URLEncoder.encode("https://client.example.org/cb", StandardCharsets.UTF_8.name())
    
        // Preparar authorization_details como un JSON codificado
        val authorizationDetails = mapOf(
            "type" to "openid_credential",
            "format" to "jwt_vc_json",
            "credential_definition" to mapOf(
                "type" to listOf("VerifiableCredential", "UniversityDegreeCredential")
            )
        )

        val authorizationDetailsJson = Gson().toJson(authorizationDetails)
        val authorizationDetailsEncoded = URLEncoder.encode(authorizationDetailsJson, StandardCharsets.UTF_8.name())
    
        // Construir la URL de la solicitud con los parámetros de consulta
        val url = URLBuilder(ENDPOINT_AUTH).apply {
            parameters.append("response_type", responseType)
            parameters.append("client_id", clientId)
            parameters.append("code_challenge", challenge)
            parameters.append("code_challenge_method", codeChallengeMethod)
            parameters.append("authorization_details", authorizationDetailsEncoded)
            parameters.append("redirect_uri", redirectUri)
        }.buildString()
    
        // Realizar la solicitud GET
        val response: HttpResponse = client.get(url)
    
        // Verificar la respuesta y obtener la URI si la respuesta es exitosa
        if (response.status == HttpStatusCode.OK) {
            val code: String = response.bodyAsText()
            println("Response: $code")
            return code
        } else {
            // Manejar los errores aquí
            println(rojo + "[!] Error: ${response.status.description}" + reset)
            throw Exception("Error during OIDC auth request: ${response.status.description}")
        }
    }
    

    suspend fun get_JWT_and_STATE(client: HttpClient, state: String, uri: String): String{

        println("")
        println(verde+"[+] GET JWT and STATE"+reset)
        println("")


        var response = client.get(ENDPOINT_CODE) {
            url {
                parameters.append("uri", uri)
                parameters.append("state", state)
            }
        }

        val texto: String = response.bodyAsText()
        return texto

    }

    suspend fun get_OIDC_discovery_document(client: HttpClient): String{
        println("")
        println(verde+"[+] GET OIDC discovery document"+reset)
        println("")

        
        val issuer = OIDC4CIService.getWithProviderMetadata(OIDCProvider(ENDPOINT_LIST_CREDENTIALS, ENDPOINT_LIST_CREDENTIALS))

        println("---")
        var x = 0
        OIDC4CIService.getSupportedCredentials(issuer).forEach { supported_cred ->
            println("Issuable credentials:")
            println("${x}- ${supported_cred.key}")
            println("---")
            x++
        }

        print("Selecciona que tipo de credencial deseas crear:")
        //val credentialTypes = readLine()
        val credentialTypes="VerifiableId"
        println("")
        println(verde+"[+] Credential selected -> ${credentialTypes}"+reset)
        println("")

        return credentialTypes.toString()
    }


    fun generateDidProof(did: String, nonce: String): JwtProof {
        val didObj = DidService.load(did)
        val vm = (didObj.authentication ?: didObj.assertionMethod ?: didObj.verificationMethod)?.firstOrNull()?.id ?: did
        return JwtProof(
            jwt = JwtService.getService().sign(
                vm,
                JWTClaimsSet.Builder()
                    .issuer(did) // Utiliza el DID como emisor en lugar de issuer.client_id o did
                    .issueTime(Date())
                    .claim("nonce", nonce)
                    .build().toString()
            ),
        )
    }


    fun generarStateAleatorio(): String {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)

        val base64String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    
        val state = base64String.substring(0, 16) + "-" + base64String.substring(16)
        
        return state
    }



    /* 
    fun getPublicKey(keyId: String): String {
        var publicKey  = ""
        SqlDbManager.getConnection().use { connection ->
            connection.prepareStatement("select * from lt_key where name = ?").use { statement ->
                statement.setString(1, keyId)
                statement.executeQuery().use { result ->
                    if (result.next()) {
                        publicKey = result.getString("pub")
                    }
                }
                connection.commit()
            }
        }
        return publicKey
    }
    */


    fun String.sha256(): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(this.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}