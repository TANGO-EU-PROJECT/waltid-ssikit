package id.walt.cli

import com.github.ajalt.clikt.core.CliktCommand
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.io.File
import java.time.Instant
import io.ktor.server.netty.*
import id.walt.crypto.*
import id.walt.services.did.DidService
import id.walt.services.key.KeyService
import io.ktor.server.engine.*
import java.security.KeyStore
import java.io.FileInputStream
import kotlinx.coroutines.runBlocking
import id.walt.services.jwt.WaltIdJwtService
import io.ktor.http.*
import id.walt.model.DidMethod
import id.walt.services.OIDC_UMU.issuer.*
import id.walt.services.OIDC_UMU.sha256
import id.walt.services.keyUmu.KeyServiceUmu
import id.walt.services.storeUmu.KeyStoreServiceUmu
import io.ktor.server.http.content.*
import io.ktor.server.plugins.cors.*
import mu.KotlinLogging
import java.util.*
import kotlin.collections.HashSet



/* SSIKIT issuer */
class IssuerCommand :
    CliktCommand(
        name = "issuer",
        help =
        """
                        OIDC4VC issuer
                """
    ) {
    /*

        Estructura que almacena la información asociada al token auth:
            -codeVerifier: Hash del nonce enviado por el usuario (mecanismo de seguridad PKCE)
            -code: valor aleatoria que representar el token del uusario
            -type: Tipo de credenciales que desea obtener.
            -CredentialSubject: Contenido de la credential.
            -expiration: Tiempo de expiración del token (1 min)

    */

    data class AuthRequest(
        val codeVerifier: String,
        val code: String,
        val credentialtype: String,
        val credentialSubject: Map<String, Any>,
        val expiration: Instant = Instant.now().plusSeconds(60),
        val redirecUri: String,
        val authType: AuthType,
        val clientId: String? = null
    )

    enum class AuthType {
        NORMAL,
        EPASSPORT,
        LATE
    }


    /*

        Estructura que almacena la información asociada a un Acces token
            -Bearer: JWT
            -nonce.
            -ExpirationTime: Tiempo de expiración (1 min)

    */

    data class TokenInfo(val bearer: String, val nonce: String ,val expirationTime: Instant)

    // Mapa que asocia a cada ClientID un token auth utilizado para la solicitud del access token
    val authRequestRegistry = mutableMapOf<String, AuthRequest>()
    // Mapa que asocia a cada clientID (tras iniciar sesión) su clientSecret
    val clientID = mutableMapOf<String, clientIdValues>()
    // Mapa que almacena los nombres de los usuarios y las contraseñas (SHA256)
    val clientCredentials = mutableMapOf<String, String>()
    // Mapa encargado de asocida a un client Id el objeto con la información de un access Token
    val tokenRegistry = mutableMapOf<String, TokenInfo>()
    // Variable que almacena los tipos de credenciales admitidas
    val credentialTypes = arrayOf("PermanentResidentCard")

    val userDetails = mutableMapOf<String, userData>()

    val local = System.getenv("LOCAL").toBoolean()

    data class clientIdValues(
        var clientsecret: String,
        var username: String
    )

    data class userData(
        var givenName: String,
        var familyName: String,
        var gender: String,
        var birthDate: String,
        var birthCountry: String
    ) {
        override fun toString(): String {
            return """{"givenName": "$givenName", "familyName": "$familyName", "gender": "$gender", "birthDate": "$birthDate", "birthCountry": "$birthCountry"}"""
        }
    }


    // DID del emisor
    lateinit var DID_BACKEND: String
    // ID de la clave asociada al DID del emisor
    lateinit var KEY_ALIAS: String

    lateinit var DID_BACKEND_LOCAL_PSMS: String
    lateinit var DID_BACKEND_LOCAL_EdDSA: String
    lateinit var KEY_ALIAS_LOCAL: String

    private val ISSUER_PORT = System.getenv("ISSUER_PORT").toInt()

    // Servicios
    val keyService = KeyService.getService()
    val jwtService = WaltIdJwtService()
    private val keyStoreUmu = KeyStoreServiceUmu.getService()
    private val keyServiceUmu = KeyServiceUmu.getService()

    // Directorio con los certificados https
    val currentWorkingDir = System.getProperty("user.dir")
    val keyStorePath = "$currentWorkingDir/cert/issuer/issuer.p12"

    // Salida mas legible
    val verde = "\u001B[32m"
    val rojo = "\u001B[31m"
    val reset = "\u001B[0m"

    lateinit var authOIDC: AuthOIDC
    lateinit var tokenOIDC: TokenOIDC
    lateinit var credentailOIDC: CredentialOIDC
    var clientIdOauth = ClientIdOauth()
    override fun run() {

        initialization()

        runBlocking {
            var keyStoreFile = File(keyStorePath)

            val keyStorePassword = ""
            val privateKeyPassword = ""
            val keyAlias = "issuer"
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(FileInputStream(keyStoreFile), keyStorePassword.toCharArray())

            val environment = applicationEngineEnvironment {
                val log = KotlinLogging.logger {}
                connector {
                    port = ISSUER_PORT
                }
                sslConnector(
                    keyStore = keyStore,
                    keyAlias = keyAlias,
                    keyStorePassword = { keyStorePassword.toCharArray() },
                    privateKeyPassword = { privateKeyPassword.toCharArray() }
                ) {
                    port = ISSUER_PORT+100
                }
                module {

                    // Políticas CORS
                    install(CORS) {
                        allowCredentials = true
                        allowNonSimpleContentTypes = true
                        allowSameOrigin = true
                        anyHost()  // Permite solicitudes CORS desde cualquier origen
                        allowHeader(HttpHeaders.ContentType)
                    }


                    routing {

                        static("/static") {
                            resources("static")
                        }

                        get("/") {
                            val indexHtml = javaClass.classLoader.getResource("static/issuer/main/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/login") {
                            val indexHtml = javaClass.classLoader.getResource("static/issuer/login/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/register") {
                            val indexHtml = javaClass.classLoader.getResource("static/issuer/register/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/form") {
                            val indexHtml = javaClass.classLoader.getResource("static/issuer/form/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }

                        get("/auth-late/form") {
                            val indexHtml = javaClass.classLoader.getResource("static/issuer/auth-late/index.html")
                            if (indexHtml != null) {
                                val content = indexHtml.readText()
                                call.respondText(content, ContentType.Text.Html)
                            } else {
                                call.respond(HttpStatusCode.NotFound)
                            }
                        }


                        get("CredentialOffer"){
                            call.respondText(generateCredentialOffer(ISSUER_PORT, credentialTypes))
                        }

                        /*
                            Registro de un usuario en el backend, contraseña se guarda en sha-256
                        */

                        post("/registerBackend") {
                            clientIdOauth.register(call,clientID,clientCredentials,userDetails)
                        }

                        /*
                            Login de un usuario
                        */

                        post("/loginBackend") {
                            clientIdOauth.login(call,clientID,clientCredentials,userDetails)
                        }



                        /*
                            Endpoint que devuelve los metadatos del emisor, credenciales que puede emitir...
                        */

                        get("/.well-known/openid-credential-issuer"){

                            println("\n$verde[+] Issuer: GET OIDC discovery document$reset\n")
                            call.respond(generateMetadata(ISSUER_PORT = ISSUER_PORT, credentialTypes))
                        }

                        /*
                            Endpoint que devuelve los metadatos de autenticación
                        */

                        get("/.well-known/oauth-authorization-server"){

                            println("\n$verde[+] Issuer: GET oauth discovery document$reset\n")
                            call.respond(generateAuthMetadata(ISSUER_PORT = ISSUER_PORT))
                        }

                        /*

                            Endpoints que comienzan con el flujo de emisión del auth token, genera parte del token, pero no lo devuelve hasta
                            completar la comunicación con el endpoint code.

                            (Desde que comienza este paso se dispone de 1 min para que expire el token)


                        */

                        get("/auth") {
                            authOIDC.auth(call,clientID,authRequestRegistry)
                        }

                        get("/auth-late") {
                            authOIDC.auth_late(call,clientID,authRequestRegistry)
                        }


                        get("/auth-ePassport") {
                            authOIDC.auth_ePassport(call,clientID,authRequestRegistry)
                        }

                        get("/getCliendId-data"){
                            val clientid = call.parameters["clientid"]
                            if (clientid == null) call.respond(HttpStatusCode.BadRequest, "clientId is required")
                            else {
                                if (clientID[clientid] != null) {
                                    val username = clientID[clientid]!!.username
                                    val userData = userDetails[username]
                                    if (userData != null) {
                                        call.respond(userData.toString())
                                    } else {

                                        call.respond(HttpStatusCode.NotFound, "No user data found for clientId: $clientid")
                                    }
                                } else {
                                    call.respond(HttpStatusCode.NotFound, "No user data found for clientId: $clientid")
                                }
                            }
                        }

                        /*

                            Endpoints que finalizan el proceso de emisión del auth Token, registra los atributos del credential subject
                            y devuelve el auth token al usuario para que pueda obtener un access token.

                        */

                        post("/code") {
                            authOIDC.code(call,clientID,authRequestRegistry)
                        }

                        post("/code-late") {
                            authOIDC.code_late(call,clientID,authRequestRegistry)
                        }

                        post("/code-ePassport") {
                            authOIDC.code_ePassport(call,clientID,authRequestRegistry)
                        }



                        /*

                            Endpoint encargada de la emisión del access token, recibe un auth token, cliendId, clientSecret... Si tras realizar toda
                            la verificación todo resulta correcto generará y devolverá el token.

                        */

                        post("/token") {
                            tokenOIDC.token(call,clientID,authRequestRegistry,tokenRegistry)
                        }

                        /*

                            Endpoint que tras realizar las comprobaciones relacionadas con el accesstoken devuelve la credencial firmada por el issuer

                        */

                        post("/credential"){
                            credentailOIDC.credential(call,tokenRegistry,authRequestRegistry)
                        }

                    }
                }
            }

            embeddedServer(Netty, environment).start(wait = true)

        }

    }

    fun initialization(){

        val attrNames_2: Set<String> = HashSet<String>(
            Arrays.asList(
                "http://schema.org/familyName",
                "http://schema.org/birthDate",
                "http://schema.org/gender",
                "http://schema.org/givenName",
                "https://w3id.org/citizenship#birthCountry"
            ))

        val kid_key = keyService.generate(KeyAlgorithm.EdDSA_Ed25519)

        val kid_fabric = keyServiceUmu.generate(attrNames_2)
        keyStoreUmu.addAlias(kid_fabric, kid_key.id)
        if (local){

            DID_BACKEND_LOCAL_EdDSA = DidService.create(DidMethod.key,kid_key.id)
            //keyService.addAlias(kid_key,DID_BACKEND_LOCAL_EdDSA)
            KEY_ALIAS = DID_BACKEND_LOCAL_EdDSA
            DID_BACKEND_LOCAL_PSMS = DidService.createUmu(kid_fabric.id,DidMethod.keyumu)
            println(DID_BACKEND_LOCAL_EdDSA)
            authOIDC = AuthOIDC(DID_BACKEND_LOCAL_EdDSA,KEY_ALIAS)
            tokenOIDC = TokenOIDC(DID_BACKEND_LOCAL_EdDSA,KEY_ALIAS)
            credentailOIDC = CredentialOIDC(DID_BACKEND_LOCAL_PSMS,kid_fabric.id)
        }
        else
        {
            KEY_ALIAS = kid_key.id
            DID_BACKEND = DidService.createUmu(kid_fabric.id,DidMethod.fabric,null,kid_key.id)
            //DID_BACKEND = DidService.createUmuMultiKey(kid_key.id,15)
            println("issuer did: "+DID_BACKEND)
            authOIDC = AuthOIDC(DID_BACKEND,KEY_ALIAS)
            tokenOIDC = TokenOIDC(DID_BACKEND,KEY_ALIAS)
            credentailOIDC = CredentialOIDC(DID_BACKEND,KEY_ALIAS)
        }

        clientCredentials["admin"] = "admin".sha256()

    }
}

