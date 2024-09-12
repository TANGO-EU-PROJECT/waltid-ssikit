package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.google.gson.Gson
import com.nimbusds.oauth2.sdk.AuthorizationRequest as AuthorizationRequestOauth
import id.walt.common.KlaxonWithConverters
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.crypto.KeyAlgorithm
import id.walt.custodian.Custodian
import id.walt.model.DidMethod
import id.walt.services.OIDC_UMU.issuer.Metadata
import id.walt.services.OIDC_UMU.issuer.generateMetadataJson
import id.walt.services.OIDC_UMU.generarValorAleatorio
import id.walt.services.OIDC_UMU.wallet.*
import id.walt.services.did.DidService
import id.walt.services.jwt.WaltIdJwtService
import id.walt.services.key.KeyService
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.oidc.OIDC4VPService
import id.walt.services.storeUmu.KeyStoreServiceUmu
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.http.content.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import java.io.File
import java.io.FileInputStream
import java.net.URI
import java.security.KeyStore
import java.util.*


/* SSIKIT issuer */
class WebWalletCommand:
    CliktCommand(
        name = "web-wallet",
        help = "Start web wallet"
    ) {

    // Servicios

    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()
    private val URI_DSC = System.getenv("URI")

    private val WALLET_PORT = System.getenv("WALLET_PORT").toInt()

    // ENDPOINTS ISSUER

    val ENDPOINT_OBTAIN_CREDENTIAL = "https://$URI_DSC/wallet/New-Credential"


    // Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"

    // DID
    val jwtService = WaltIdJwtService()
    val currentWorkingDir = System.getProperty("user.dir")
    val keyStorePath = "$currentWorkingDir/cert/webWallet/webWallet.p12"

    data class IssuerCredentials(
        var clientid: String,
        var clientsecret: String
    )

    // GLOBAL
    lateinit var challenge: String
    lateinit var last_vp_token: String
    lateinit var last_authorization_request: AuthorizationRequestOauth
    val keyService = KeyService.getService()
    lateinit var credentialOffer: CredentialOffer
    var metadata: Metadata? = null
    lateinit var DID_BACKEND: String
    lateinit var KEY_ALIAS: String
    var last_AccessToken: String? = null
    var last_authCode: String? = null
    var issuerCredentials: IssuerCredentials? = null
    var last_credentialId: String? = null
    var ePassport = false
    val metadataRequest = MetadataRequest()
    var authorizationRequest: AuthorizationRequest? = null
    var credentialRequest: CrendentialRequest? = null
    val MODE = System.getenv("MODE")
    val local = System.getenv("LOCAL").toBoolean()

    override fun run() {

        initialization()

        runBlocking {
            var keyStoreFile = File(keyStorePath)
            val keyStorePassword = ""
            val privateKeyPassword = ""
            val keyAlias = "webWallet"
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())

            val environment = applicationEngineEnvironment {
                val log = KotlinLogging.logger {}
                connector {
                    port = WALLET_PORT
                }
                sslConnector(
                    keyStore = keyStore,
                    keyAlias = keyAlias,
                    keyStorePassword = { keyStorePassword.toCharArray() },
                    privateKeyPassword = { privateKeyPassword.toCharArray() }
                ) {
                    port = WALLET_PORT+100
                }
                module {

                    install(CORS) {
                        allowCredentials = true
                        allowNonSimpleContentTypes = true
                        allowSameOrigin = true
                        anyHost()  // Permite solicitudes CORS desde cualquier origen
                        allowHeader(HttpHeaders.ContentType)
                    }

                    routing {

                        /*

                        Endpoints para obtener el frontend del wallet

                        */

                        static("/static") {
                            resources("static")
                        }

                        get("/") {
                            val indexHtml = javaClass.classLoader.getResource("static/wallet/main/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/credentials") {
                            val indexHtml = javaClass.classLoader.getResource("static/wallet/credentials/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/error") {
                            val indexHtml = javaClass.classLoader.getResource("static/wallet/error/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/New-Credential") {
                            val code = call.request.queryParameters["code"]
                            val clientid = call.request.queryParameters["clientid"]
                            val clientsecret = call.request.queryParameters["clientsecret"]

                            if (!clientid.isNullOrBlank() && !clientsecret.isNullOrBlank()) {
                                issuerCredentials = IssuerCredentials(
                                    clientid = clientid,
                                    clientsecret = clientsecret
                                )
                            }

                            if (code == null || code == "") {
                                call.respond(HttpStatusCode.InternalServerError, "Error: Invalid Auth code.")
                            }
                            else{
                                last_authCode = code
                                val indexHtml = javaClass.classLoader.getResource("static/wallet/newCredentials/index.html")
                                if (indexHtml != null) {
                                    val content = indexHtml.readText()
                                    call.respondText(content, ContentType.Text.Html)
                                } else {
                                    call.respond(HttpStatusCode.NotFound)
                                }
                            }
                        }

                        get("/Configuration") {

                            val indexHtml = javaClass.classLoader.getResource("static/wallet/configuration/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }

                        }

                        get("/selectCredential") {
                            val indexHtml = javaClass.classLoader.getResource("static/wallet/selectCredential/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/verifyCredential") {
                            val vpToken = call.request.queryParameters["vpToken"]
                            if (vpToken==null && last_vp_token==null) throw IllegalArgumentException("Invalid vpToken.")
                            if (vpToken!=null) last_vp_token = vpToken
                            val indexHtml = javaClass.classLoader.getResource("static/wallet/verifyCredential/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        /*

                        Endpoints del backend

                        */

                        get("/openid-credential-offer") {
                            val issuerCred = metadataRequest.getIssuerCredentials(call)
                            if (issuerCred != null) issuerCredentials = issuerCred
                            val credentialOff = metadataRequest.getCredentialOffer(call)
                            if (credentialOff != null){
                                credentialOffer = credentialOff
                                metadata = metadataRequest.getMetadata(call,credentialOffer)
                            }
                        }

                        get("/Config") {
                            println("\n$verde[+] Wallet: Show metadata$reset\n")
                            if(metadata != null){
                                call.respond(generateMetadataJson(metadata!!))
                            }
                            else {
                                call.respond(HttpStatusCode.InternalServerError, "Error: Credential offer is not initialized.")
                            }
                        }

                        get("/list-credentials") {
                            if (!::credentialOffer.isInitialized) {
                                call.respond(HttpStatusCode.InternalServerError, "Error: Credential offer is not initialized.")
                            } else {
                                val gson = Gson()
                                val json = gson.toJson(credentialOffer.credentialConfigurationIds)
                                call.respond(json)
                            }
                        }

                        /*

                            Comienza el proceso apra obtener el auth Token (este endpoint devuelve la url donde se
                            especificarán los parámetros del credential Subject)

                        */

                        post("/credentialParameters"){

                            val parameters = call.receiveParameters()
                            val template = parameters["credentialId"]
                            val redirect = parameters["redirecturi"]

                            if (template == null)
                                throw IllegalArgumentException("Invalid parameters")
                            else if (metadata == null){
                                throw IllegalArgumentException("Invalid Metadata")
                            }
                            last_credentialId = template
                            challenge = generarValorAleatorio()
                            if (redirect != null) authorizationRequest!!.authRequest(call,template,challenge,issuerCredentials,ePassport,metadata!!, redirect)
                            else authorizationRequest!!.authRequest(call,template,challenge,issuerCredentials,ePassport,metadata!!)
                        }


                        /*

                            Completa la creación de la credencial:
                                -1: Realiza el segundo paso para obtener el auth token (especificando los valores del credential Subject)
                                -2: Intercambiar el auth_token por el access_token.
                                -3: Solicita la creación de la credencial.
                                -4: Devuelve la credencial generada

                        */

                        get("/createCredential"){

                            if (metadata != null && last_credentialId != null && last_authCode != null){

                                // ACCESS TOKEN
                                last_AccessToken  = credentialRequest!!.accessTokenRequest(metadata!!,ePassport,issuerCredentials,last_authCode!!,challenge, "example.com")
                                // CREDENTIAL
                                val credential = credentialRequest!!.credentialRequest(metadata!!, last_AccessToken!!)

                                log.debug{"createCredential -> [!] WebWallet logs: credential - ${credential}"}
                                call.respond(credential)
                            }
                            else
                            {
                                throw IllegalArgumentException("Invalid parameters")
                            }

                        }


                        /*

                            Devuelve el listado de credenciales almacenadas en el wallet

                        */

                        get("/listCredentials"){
                            call.respond(listCredential())
                        }

                        /*

                            Endpoint para almacenar una credencial que hemos recibido del issuer

                        */

                        post("/storeCredential"){
                            val parameters = call.receiveParameters()
                            val credential = parameters["credential"]
                            val name = parameters["nameCred"]
                            if (credential == null || name == null) throw IllegalArgumentException("Invalid parameters")
                            log.debug{"storeCredential -> [!] WebWallet logs: name - ${name}"}
                            saveCredential(credential,name)
                        }

                        /*

                            Elimina una credencial que se encuentra almacenada en el wallet

                        */

                        post("/deleteCredential"){
                            val parameters = call.receiveParameters()

                            val name = parameters["nameCred"]
                            if (name == null) throw IllegalArgumentException("Invalid parameters")

                            deleteFile(name)
                            log.debug{"deleteCredential -> [!] WebWallet logs: name - ${name}"}
                        }

                        /*

                            Parsea los datos del último vp token (política solicitada) y lo devuelve para que se muestre por
                            pantalla (demo).

                        */

                        get("/vpTokenDetails"){
                            if (last_vp_token == null) throw IllegalArgumentException("Invalid parameters")
                            log.debug{"vpTokenDetails -> [!] WebWallet logs: vpTokenDetails - ${vpTokenDetails(last_vp_token!!)}"}
                            call.respond(vpTokenDetails(last_vp_token!!))
                        }

                        /*
                            Comprueba del listado de credenciales que hay en local cuales cumples la política
                            solicitada.

                            Devuelve el listado que cumplen la política
                        */

                        get("/validCredentials"){
                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }


                            val list = obtainValidCredentialsDemo(client)
                            log.debug{"validCredentials -> [!] WebWallet logs: list - ${list}"}
                            call.respond(list)

                            client.close()
                        }

                        /*

                            Selecciona una credencial para generar la presentación que satisface la política solicitada. Además se comunica
                            con el verifier para generar el JWT que autorice al usuario.

                        */

                        post("/selectCredential") {
                            val credential = call.receiveText()
                            if (credential.isEmpty()) throw IllegalArgumentException("Invalid parameters")

                            val client = HttpClient() {
                                install(ContentNegotiation) { json() }
                                expectSuccess = false
                            }
                            // Función para generar una derivación de una credencial con zkp
                            val result = DeriveCredential(client, credential,DID_BACKEND,last_authorization_request,KEY_ALIAS,last_authorization_request.redirectionURI.toString())
                            // Función si queremos generar una presentación sin zkp
                            // val result = VerfiablePresentation(client, credential)
                            log.debug{"selectCredential -> [!] WebWallet logs: result - ${result}"}

                            call.respond(result)

                            client.close()
                        }
                    }

                }
            }

            embeddedServer(Netty, environment).start(wait = true)
        }
    }

    // Obtención del listado de credenciales que satisfacen una política dada.

    suspend fun obtainValidCredentialsDemo(client: HttpClient): String {

        println("\n$verde[+] Wallet: Obtain valid credentials $reset\n")

        val req = OIDC4VPService.parseOIDC4VPRequestUri(URI.create(last_vp_token))
        if (req == null){
            println("Error parsing SIOP request")
            return """{"error": "Error parsing SIOP request"}"""
        }
        val presentationDefinition = OIDC4VPService.getPresentationDefinition(req)
        last_authorization_request = req
        val (credentialTypes,paths ,credentialSubjectAttributes) = extractPresentationDefinitionInfo(KlaxonWithConverters().toJsonString(presentationDefinition))
        val list = verifyCredentials(credentialTypes,paths ,credentialSubjectAttributes)
        var creds = "{"
        list.forEachIndexed { index, vc ->
            creds += "\"${index + 1}\": [ $vc ]"
            if (index < list.size - 1) {
                creds += ","
            }
        }
        creds += "}"

        return creds
    }

    // Función que recorrer el listado de credenciales almanceandas para ver el listado de ellas que cumplen una determinada política

    fun verifyCredentials(
        credentialTypes: List<String>,
        credentialSubjectAttributesFullPath: List<String>,
        credentialSubjectValues: List<String>
    ): List<VerifiableCredential> {
        val matchingCredentials = mutableListOf<VerifiableCredential>()
        val verifiableCreds = Custodian.getService().listCredentials()
        val credentialSubjectAttributes = credentialSubjectAttributesFullPath.map { it.split(".").last() }

        verifiableCreds.forEach { vc ->
            if (vc.type.any { credentialTypes.contains(it) }) {
                val credentialSubject = vc.credentialSubject ?: return@forEach
                val matchesAllAttributes = credentialSubjectAttributes.indices.all { index ->
                    val attributeKey = credentialSubjectAttributes[index]
                    val expectedValue = credentialSubjectValues[index]
                    val actualValue = credentialSubject.properties[attributeKey]?.toString()

                    expectedValue == actualValue
                }
                if (matchesAllAttributes) {
                    matchingCredentials.add(vc)
                }
            }
        }

        return matchingCredentials
    }


    fun initialization(){



        val kid_key = keyService.generate(KeyAlgorithm.EdDSA_Ed25519)


        if(MODE == "ePassport") ePassport = true
        if (local){
            DID_BACKEND = DidService.create(DidMethod.key, kid_key.id)
            KEY_ALIAS = DID_BACKEND
        }
        else {
            KEY_ALIAS = kid_key.id
            val attrNames_2: Set<String> = HashSet(
                Arrays.asList(
                    "http://schema.org/familyName",
                    "http://schema.org/birthDate",
                    "http://schema.org/gender",
                    "http://schema.org/givenName",
                    "https://w3id.org/citizenship#birthCountry"
                )
            )

            val kid_fabric = keyServiceUmu.generate(attrNames_2)
            keyStoreUmu.addAlias(kid_fabric, kid_fabric.id)

            //DID_BACKEND = DidService.createUmuMultiKey(kid_key.id, 15)

            DID_BACKEND = DidService.createUmu(kid_fabric.id,DidMethod.fabric,null,kid_key.id)
        }


        authorizationRequest = AuthorizationRequest(WALLET_PORT, ENDPOINT_OBTAIN_CREDENTIAL, DID_BACKEND)
        credentialRequest = CrendentialRequest(DID_BACKEND,KEY_ALIAS)
        println("webwallet did: "+DID_BACKEND)
    }
}
