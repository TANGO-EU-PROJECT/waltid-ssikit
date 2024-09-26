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
import java.util.Base64



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

                        get("/ScanQR") {

                            val indexHtml = javaClass.classLoader.getResource("static/wallet/scanqr/index.html")
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

                        get("/getCredential"){


                            val verifiableCreds = Custodian.getService().listCredentials()
                            val cred = verifiableCreds[0].toString()
                            //val base64UrlHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(cred.toByteArray())
                            //call.respondText(base64UrlHeader, ContentType.Text.Plain)
                            //val frame = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://w3id.org/citizenship/v1\",\"https://ssiproject.inf.um.es/security/psms/v1\"],\"@type\":[\"VerifiableCredential\",\"PermanentResidentCard\"],\"credentialSubject\":{\"@type\":\"PermanentResident\",\"@explicit\":true,\"givenName\":{},\"gender\":{}}}"
                            //val nonce = generarValorAleatorio()
                            //val jsonString = credential.trimIndent()
                            //val jsonElement = Json.parseToJsonElement(jsonString)
                            //val issuer = jsonElement.jsonObject["issuer"]?.toString()?.replace("\"", "")
                            //val deriveVC = jsonLdCredentialService.deriveVC(credential, issuer = issuer, challenge = nonce, frame = frame, domain = null, expirationDate = null);
                            //val presentation = createVerifiablePresentation(deriveVC, DID_BACKEND).toVerifiablePresentation()

                            val value = "eyJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSJdLCJpZCI6InVybjp1dWlkOmE1ZmM2ZjQzLWI3ZDQtNDU2Ni1iNmIyLWU4MjZiODU0MzA1YSIsInByb29mIjp7InR5cGUiOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImNyZWF0b3IiOiJkaWQ6a2V5Ono2TWtxQ2dOaHAySkVrWThVdWoyYlhhMkd0SkxMbjhSU2hjY2MzbnZYZTdvYkdqdCIsImNyZWF0ZWQiOiIyMDI0LTA5LTE5VDA5OjExOjM3WiIsInByb29mUHVycG9zZSI6ImF1dGhlbnRpY2F0aW9uIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOmtleTp6Nk1rcUNnTmhwMkpFa1k4VXVqMmJYYTJHdEpMTG44UlNoY2NjM252WGU3b2JHanQjejZNa3FDZ05ocDJKRWtZOFV1ajJiWGEyR3RKTExuOFJTaGNjYzNudlhlN29iR2p0IiwiandzIjoiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpGWkVSVFFTSjkuLmlrQlg2WjJjakJJa21hYXJXM3Y0LU9ueHFxMXFhaVNOSktfdDFPUnZIbVVVXzRWY0pkZk5CR0ZqajdNYld2dUhNd3JxOVJyRTdlWFhyWFY1RnJaQUF3In0sImhvbGRlciI6ImRpZDprZXk6ejZNa3FDZ05ocDJKRWtZOFV1ajJiWGEyR3RKTExuOFJTaGNjYzNudlhlN29iR2p0IiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJQZXJtYW5lbnRSZXNpZGVudENhcmQiXSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL2NpdGl6ZW5zaGlwL3YxIiwiaHR0cHM6Ly9zc2lwcm9qZWN0LmluZi51bS5lcy9zZWN1cml0eS9wc21zL3YxIl0sImlkIjoidXJuOnV1aWQ6NzMzYmM1MWQtYWU0ZS00NzJhLWI1YTctYWExNWQ4NzY5ZGRjIiwiaXNzdWVyIjoiZGlkOmtleXVtdTpYQkFlRk1zWDJLb3lkdktueURGY2kzRjRZM1VLeTIzdGJ5UzVneWFHOW9OVWRXUXhUczRyc1YzVGtINGZzY0o2eVFuTkRjRmdTcXl3MmRBRVhEZWtNTjhBQ0t3aEVNVTNDZ0hyb1VibjZiZjJyUUdjNzhFY0w3dVlGVEJobjZWaTNheVVtOTNVWVc5YWdOTFhaOFlVbkZpOEtmcG9TYnVlTG04NjlVRkdGODlGd0E2NXl1aE1xYXducDJHeVVDUXVYUDVBYW5mWEZvR1pUVGRxcm5KM3lyVERKTHhwdjFwTDNTbzZQMlVTVDJxa1UzR1BRM1d5eG5tQWE1aEhuS2VnNGF4TkZzQjdVUkRoVUZGWXhmWmJ3cGVFeE5OUG1mVGI2R3NFWFhMSlU0bXBmZ3dqNHJCZGp3TWJlbUJ3RmJ2elk0U1p5SktyUXpOekV0M3hiWGlKUXNRZW52Q0N3czFwSHhhMXlIcmtRQW9jRE1rd2lWV3R5ajVvdjh1RTRGbXI1aTc3SEw3QUdjQU5wRVFTa0FGaEVYNW13Y2U2eDdLbUhmWXpKWjJQQjVXZ2ljcmthbWRUaUNUNGpLbVZaYXlEWnVKTWFlODRGSzhKSm5GckpTSEpvOTloVUZFcUM1elB3ak5BcW5xZTdhZjVxVGh4aWNKMThCOXlnTTdNRzdyNWJib1pveTRaMWdpZ2p4czhVRHBNb0U1Y0hra0ZLNjRWNVp4dlpYTnhlY3Y0cVhXNUJjOGVZUlhpVUVWWnFxemJQdlpUVUp6a1RLVU1TV0pqSko3cVpjZGpWNERoUG1GQ0N6TFR0bVRYeEdCWDlINTQ3eGJVQUNzY2toVER2U21EeGF5RHhVaWJrVzFBM0RBOXpVYmY1aDVROGlwazNtcGdydVhGcFl5R3hLYk1WTWQ2OTJYTlVKa3paWUVQTXBzdEJ1Mnl2R1RwbzI3Yng3TEZjbkRIMWhqaDl1aFRUWkVSbkM5VE5tS2JHcG1pNkZObnQ3YWZCVUpkc05ZSGhvSHJaZG1TamYxcWFTNTNWdHZROURUYU1hZzc4MUJqVVZqNWRkRUd6WjV1Vjc2dDdCUHBuR2dZN3dwbW52d1dSZ3BxcFMycHBRUVBRYlJZM2k4d2lxbkZrdENiV2k2TVR0S1FpVVRYMTZKamZXWnlMbTFaUWF2Mzhxa0RrcEJOMzM2cVV0eDlCUjVKTUZWZmI2SlN0RkJvOUdrQ2k4ZUZ2QXpXYXExamIxdEtVWHJzdExrSFltaUhKd0FGVFEzZWtZclNxcEE4N2JiVFJiU00yQkZTNlFISG55QlE3WjFKZkJ1c0FjMXJvNXhQTFFUWkhlMzh6UjR3MVBwVTVQUld6NllDMVVZcEhOb3dqRk12Tnd3cVZiSEI4TkpuQVkyblVqc0FUUUpNOUZUTmNtOUplWXp5VlpIZFJ5VEo0TGhINkg3SFFxTXI3RVpBaEQ4NmZ6ZzNTZmdzOFJndTNlbWNLRDdvdDkzc2s0UmNneDRTalduRkFIazJablh0b3ptallWZThvenI0cDF5NU1CUTZCUGVSOHh6Q05kTHZ0ZE5KRXNreXNrMnR0aXljako3QkRTQ2JOQTd6d2ZBRDFUdmZ0TmQyQ05BVEVCTVJialpKMmhUVkxuZ3hRUllQWkZKblpCdmd6a2QzOGVoU25pUG5FNnpmRUYyd29MYUY4VFdTaWF0cUFoZ3g3VlB2Q3pYY3ZuZFNISm9HcHRTeEYyYktyNm1OYmp4OHI5OXlBdEtVZHZpdVhUSHN3YlZFWlhwNUZjTXMyV042QWFNY1dmOEFxTFdOdXNodW82Z1AzWDI4Q2Y3TGhITXFhamc3VnNXMVpXbXNWTG9QWXRKVUY5aUpMcmhNY1lrWGdORFBCM0w1a0dQV2szRTJFVjZMUHNLV21hMXZ1aUtqaTVzalE5UGRjOFJWWXBvTkxzTnZ1Q3VXQUJpdHpRcE1DUHRKVHhWTlY0UG9RWVpBWkNqOVVRUGtCYkpnQkZLZ1JYUkJiRmR4UUd4Qkc0QUVVdWRMU0ZRYTdVbkxDc3VGSlVMTlFlVEZVQm02U3ZiS2F3SzVmbWluWU1HOGRzeEhTUHlwSGJ5M3FyVVZEN21FOSIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMDktMTlUMDk6MTE6MjVaIiwiaXNzdWVkIjoiMjAyNC0wOS0xOVQwOToxMToyNVoiLCJ2YWxpZEZyb20iOiIyMDI0LTA5LTE5VDA5OjExOjI1WiIsInByb29mIjp7InR5cGUiOiJQc21zQmxzU2lnbmF0dXJlMjAyMlByb29mIiwiY3JlYXRvciI6ImRpZDprZXl1bXU6WEJBZUZNc1gyS295ZHZLbnlERmNpM0Y0WTNVS3kyM3RieVM1Z3lhRzlvTlVkV1F4VHM0cnNWM1RrSDRmc2NKNnlRbk5EY0ZnU3F5dzJkQUVYRGVrTU44QUNLd2hFTVUzQ2dIcm9VYm42YmYyclFHYzc4RWNMN3VZRlRCaG42VmkzYXlVbTkzVVlXOWFnTkxYWjhZVW5GaThLZnBvU2J1ZUxtODY5VUZHRjg5RndBNjV5dWhNcWF3bnAyR3lVQ1F1WFA1QWFuZlhGb0daVFRkcXJuSjN5clRESkx4cHYxcEwzU282UDJVU1QycWtVM0dQUTNXeXhubUFhNWhIbktlZzRheE5Gc0I3VVJEaFVGRll4Zlpid3BlRXhOTlBtZlRiNkdzRVhYTEpVNG1wZmd3ajRyQmRqd01iZW1Cd0ZidnpZNFNaeUpLclF6TnpFdDN4YlhpSlFzUWVudkNDd3MxcEh4YTF5SHJrUUFvY0RNa3dpVld0eWo1b3Y4dUU0Rm1yNWk3N0hMN0FHY0FOcEVRU2tBRmhFWDVtd2NlNng3S21IZll6SloyUEI1V2dpY3JrYW1kVGlDVDRqS21WWmF5RFp1Sk1hZTg0Rks4SkpuRnJKU0hKbzk5aFVGRXFDNXpQd2pOQXFucWU3YWY1cVRoeGljSjE4Qjl5Z003TUc3cjViYm9ab3k0WjFnaWdqeHM4VURwTW9FNWNIa2tGSzY0VjVaeHZaWE54ZWN2NHFYVzVCYzhlWVJYaVVFVlpxcXpiUHZaVFVKemtUS1VNU1dKakpKN3FaY2RqVjREaFBtRkNDekxUdG1UWHhHQlg5SDU0N3hiVUFDc2NraFREdlNtRHhheUR4VWlia1cxQTNEQTl6VWJmNWg1UThpcGszbXBncnVYRnBZeUd4S2JNVk1kNjkyWE5VSmt6WllFUE1wc3RCdTJ5dkdUcG8yN2J4N0xGY25ESDFoamg5dWhUVFpFUm5DOVRObUtiR3BtaTZGTm50N2FmQlVKZHNOWUhob0hyWmRtU2pmMXFhUzUzVnR2UTlEVGFNYWc3ODFCalVWajVkZEVHelo1dVY3NnQ3QlBwbkdnWTd3cG1udndXUmdwcXBTMnBwUVFQUWJSWTNpOHdpcW5Ga3RDYldpNk1UdEtRaVVUWDE2SmpmV1p5TG0xWlFhdjM4cWtEa3BCTjMzNnFVdHg5QlI1Sk1GVmZiNkpTdEZCbzlHa0NpOGVGdkF6V2FxMWpiMXRLVVhyc3RMa0hZbWlISndBRlRRM2VrWXJTcXBBODdiYlRSYlNNMkJGUzZRSEhueUJRN1oxSmZCdXNBYzFybzV4UExRVFpIZTM4elI0dzFQcFU1UFJXejZZQzFVWXBITm93akZNdk53d3FWYkhCOE5KbkFZMm5VanNBVFFKTTlGVE5jbTlKZVl6eVZaSGRSeVRKNExoSDZIN0hRcU1yN0VaQWhEODZmemczU2ZnczhSZ3UzZW1jS0Q3b3Q5M3NrNFJjZ3g0U2pXbkZBSGsyWm5YdG96bWpZVmU4b3pyNHAxeTVNQlE2QlBlUjh4ekNOZEx2dGROSkVza3lzazJ0dGl5Y2pKN0JEU0NiTkE3endmQUQxVHZmdE5kMkNOQVRFQk1SYmpaSjJoVFZMbmd4UVJZUFpGSm5aQnZnemtkMzhlaFNuaVBuRTZ6ZkVGMndvTGFGOFRXU2lhdHFBaGd4N1ZQdkN6WGN2bmRTSEpvR3B0U3hGMmJLcjZtTmJqeDhyOTl5QXRLVWR2aXVYVEhzd2JWRVpYcDVGY01zMldONkFhTWNXZjhBcUxXTnVzaHVvNmdQM1gyOENmN0xoSE1xYWpnN1ZzVzFaV21zVkxvUFl0SlVGOWlKTHJoTWNZa1hnTkRQQjNMNWtHUFdrM0UyRVY2TFBzS1dtYTF2dWlLamk1c2pROVBkYzhSVllwb05Mc052dUN1V0FCaXR6UXBNQ1B0SlR4Vk5WNFBvUVlaQVpDajlVUVBrQmJKZ0JGS2dSWFJCYkZkeFFHeEJHNEFFVXVkTFNGUWE3VW5MQ3N1RkpVTE5RZVRGVUJtNlN2Ykthd0s1Zm1pbllNRzhkc3hIU1B5cEhieTNxclVWRDdtRTkiLCJjcmVhdGVkIjoiMjAyNC0wOS0xOVQwOToxMTozN1oiLCJwcm9vZlB1cnBvc2UiOiJhdXRoZW50aWNhdGlvbiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDprZXl1bXU6WEJBZUZNc1gyS295ZHZLbnlERmNpM0Y0WTNVS3kyM3RieVM1Z3lhRzlvTlVkV1F4VHM0cnNWM1RrSDRmc2NKNnlRbk5EY0ZnU3F5dzJkQUVYRGVrTU44QUNLd2hFTVUzQ2dIcm9VYm42YmYyclFHYzc4RWNMN3VZRlRCaG42VmkzYXlVbTkzVVlXOWFnTkxYWjhZVW5GaThLZnBvU2J1ZUxtODY5VUZHRjg5RndBNjV5dWhNcWF3bnAyR3lVQ1F1WFA1QWFuZlhGb0daVFRkcXJuSjN5clRESkx4cHYxcEwzU282UDJVU1QycWtVM0dQUTNXeXhubUFhNWhIbktlZzRheE5Gc0I3VVJEaFVGRll4Zlpid3BlRXhOTlBtZlRiNkdzRVhYTEpVNG1wZmd3ajRyQmRqd01iZW1Cd0ZidnpZNFNaeUpLclF6TnpFdDN4YlhpSlFzUWVudkNDd3MxcEh4YTF5SHJrUUFvY0RNa3dpVld0eWo1b3Y4dUU0Rm1yNWk3N0hMN0FHY0FOcEVRU2tBRmhFWDVtd2NlNng3S21IZll6SloyUEI1V2dpY3JrYW1kVGlDVDRqS21WWmF5RFp1Sk1hZTg0Rks4SkpuRnJKU0hKbzk5aFVGRXFDNXpQd2pOQXFucWU3YWY1cVRoeGljSjE4Qjl5Z003TUc3cjViYm9ab3k0WjFnaWdqeHM4VURwTW9FNWNIa2tGSzY0VjVaeHZaWE54ZWN2NHFYVzVCYzhlWVJYaVVFVlpxcXpiUHZaVFVKemtUS1VNU1dKakpKN3FaY2RqVjREaFBtRkNDekxUdG1UWHhHQlg5SDU0N3hiVUFDc2NraFREdlNtRHhheUR4VWlia1cxQTNEQTl6VWJmNWg1UThpcGszbXBncnVYRnBZeUd4S2JNVk1kNjkyWE5VSmt6WllFUE1wc3RCdTJ5dkdUcG8yN2J4N0xGY25ESDFoamg5dWhUVFpFUm5DOVRObUtiR3BtaTZGTm50N2FmQlVKZHNOWUhob0hyWmRtU2pmMXFhUzUzVnR2UTlEVGFNYWc3ODFCalVWajVkZEVHelo1dVY3NnQ3QlBwbkdnWTd3cG1udndXUmdwcXBTMnBwUVFQUWJSWTNpOHdpcW5Ga3RDYldpNk1UdEtRaVVUWDE2SmpmV1p5TG0xWlFhdjM4cWtEa3BCTjMzNnFVdHg5QlI1Sk1GVmZiNkpTdEZCbzlHa0NpOGVGdkF6V2FxMWpiMXRLVVhyc3RMa0hZbWlISndBRlRRM2VrWXJTcXBBODdiYlRSYlNNMkJGUzZRSEhueUJRN1oxSmZCdXNBYzFybzV4UExRVFpIZTM4elI0dzFQcFU1UFJXejZZQzFVWXBITm93akZNdk53d3FWYkhCOE5KbkFZMm5VanNBVFFKTTlGVE5jbTlKZVl6eVZaSGRSeVRKNExoSDZIN0hRcU1yN0VaQWhEODZmemczU2ZnczhSZ3UzZW1jS0Q3b3Q5M3NrNFJjZ3g0U2pXbkZBSGsyWm5YdG96bWpZVmU4b3pyNHAxeTVNQlE2QlBlUjh4ekNOZEx2dGROSkVza3lzazJ0dGl5Y2pKN0JEU0NiTkE3endmQUQxVHZmdE5kMkNOQVRFQk1SYmpaSjJoVFZMbmd4UVJZUFpGSm5aQnZnemtkMzhlaFNuaVBuRTZ6ZkVGMndvTGFGOFRXU2lhdHFBaGd4N1ZQdkN6WGN2bmRTSEpvR3B0U3hGMmJLcjZtTmJqeDhyOTl5QXRLVWR2aXVYVEhzd2JWRVpYcDVGY01zMldONkFhTWNXZjhBcUxXTnVzaHVvNmdQM1gyOENmN0xoSE1xYWpnN1ZzVzFaV21zVkxvUFl0SlVGOWlKTHJoTWNZa1hnTkRQQjNMNWtHUFdrM0UyRVY2TFBzS1dtYTF2dWlLamk1c2pROVBkYzhSVllwb05Mc052dUN1V0FCaXR6UXBNQ1B0SlR4Vk5WNFBvUVlaQVpDajlVUVBrQmJKZ0JGS2dSWFJCYkZkeFFHeEJHNEFFVXVkTFNGUWE3VW5MQ3N1RkpVTE5RZVRGVUJtNlN2Ykthd0s1Zm1pbllNRzhkc3hIU1B5cEhieTNxclVWRDdtRTkjMjM3MjU2MTliOWNiNDZlOTVjMWI4MjMwNDkzOGMyN2Y5NTYxNTc1YjFmOTNjZTY1YjYzYTA3ZjJhMzNjOWI4MCIsIm5vbmNlIjoiUFkwZ2Q0eVlYdlQxMDhzOS1nbXRPX2JaZmRXQlgtemc0cWxmejI3bUUxQkUiLCJwcm9vZlZhbHVlIjoiekVlRHVOdTRuNHFRNXIydnZmbzdMaXRFa1dhUTFtNkJ6cHJIR25Ka200dGZvMTdMb0Y1UDNtQkh4WFJLMTRQU0pIU1g4cFd4eWJGSlFFM3BvR3BwVnA4Vm41R1E5Ynhxc3dMdmpMR0N2dFZqQ3ViS2dzQTZUbVp6S0hjNFBBeHpzVnRTUjRlb3dwb1pzUkVNUjYyTnI1djhxNlVQS1JjZFRoM0JuWVByTlQzZWR5NmN5aFlSbmNIaERvY3p3Z1FidXY2OXpUYlNaSjI0VzJZdTY0dmVpcjRUMTVNd013a1FvOXh2c2dUV1IyY2lEM01aYndZc3NTdG9HbVduZ29QbnhmR1c3V0VBQ1hpWkdFakVOc0hBVFdLRkd2UEZTejlMVnJObkxBZzhMQjlGTDFYNTRoaHprdVhQYmY4eGZwdDY0MkdkYjJVcXZWcEt5ZUV4aXJMYnh3aTZtM2V2QzdLRU1YYURTQVZNSmR1QjQ2SkZwV0VSRFg5enhyaWRjaGFhcG9HN1dobTRvcnVpdEpnQXV1emRIaURndTNBcHZoMjFESGFXMTdMMlBuNHdETXJ5cEpza1lvVkxCNUgxM0Fia0ZKaVZ1ODQ3NWtNZDJVUmFGNWZpS3BGeUVpTVg2ZmN0VDFRMTZQenhSbmZFWlZXMU5nTkZ2VXpBV2tFdHYxRFhBb0xIWTU3dFJhZUhoUWtBdFVGVFNoU0RmdGZqd1AxbXpuR3lUM2VRb2F4WkwyWTQ1R3dQVkV3eGJKSFB6VlNDWlM0b3FqZmNMeXZpSFRqYmtTZThGMzNxeGhqb283N3hNWFhLWG15a0VqY1FpbVlyWmdKUk41Y3NSc1BXVkNvS1JnZDR6YmVEekJMbjlXOTRVQ2pHdDVBQkQ4Z3hMM0tDVGJRdjQxVU5zdUtHUDRvQXViaHJxdVgxb2VuVlJrVnA0RjJreXIzMXJQWEU2UVpyWWI0cjN6MlBKODg5amJDYlhldmV1bmp1aEdTMjNSWURNUHNYYUNpNWVYSmFQU2hwQnJNOHpQZFJrejI3b0s2UFM1VzdiSzZoTkNGNEVraG1oWjFXZW5CMU1HcWVvYUFVUHc0bnVmTURuaFl1YlZnYVJiZzF4clhOV3loWnNpelh5c3J2NHdhSjNUREVRbTRHOUN0a3dlZFBndzJDUkhyQjZxdld5c2dtRlBER0VEY2ZOYWZxMjZLOEEyNko3cld6ekRyZnVma1JyVDZMWkFIS3FZZkxxd3paeTRrQjZ2Smhid2NGU0NmM3pOM1NwaTFYMmY3Z2NyRW83b2pLeWtzY2JiQWZzSGNTZlhEcUV0SjlGYm13TmJ2TkQ2WkUyNXRRanRrYTdBdTNRbmFzeHdwWmI2TTVVMWkzWXg1OFh3d2FTbWprN211ZEpqYzk5aVpxN1hBS25KdUNXOTZyZDJoa0tqRjhQWXFYa21YaXR5NUIzTWkycDJZbTV1bnprUThONFY2VThmNkV2Rzl4MTltZjQxQm91QnlhcjFQd1RXQkdhM2hmazVUTGdjZkRZaDVOZGI2RG5vcHVYSFFtcWlEVmV2OUZKZHlHRW1mMlYycllrWEZlM2J4Nzc1TEt1RUttZkVhWGRoY2NaMzhhNFlhZnA2OHBZNHdmdFJCZGtIc3Jhc0VkYzVVZUZib0RWWjFXVkhzQ3hLVDJUUXpEUjd0S2tqMllFTGhwM3NnSnBmSlBxN21xQnRBQmc0ZGppVjFlSDlNemczZlh3Z2NYNXRCN1M3aGVVSzlyblE4WVRSVVYifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6a2V5Ono2TWtxQ2dOaHAySkVrWThVdWoyYlhhMkd0SkxMbjhSU2hjY2MzbnZYZTdvYkdqdCIsInR5cGUiOiJQZXJtYW5lbnRSZXNpZGVudCIsImdlbmRlciI6Ik1hbGUiLCJnaXZlbk5hbWUiOiJQZWRybyJ9LCJuYW1lIjoidGVzdCIsInNlYzpwcm9vZiI6e319XSwiYWxnIjoiSFMyNTYifQ"

                            call.respond(value)
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
