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

                            val jwtHeader = Gson().toJson(cred)
                            val jwtPayload = "{}"
                            val jwt = Base64.getUrlEncoder().encodeToString(jwtHeader.toByteArray()) + "." +
                                    Base64.getUrlEncoder().encodeToString(jwtPayload.toByteArray())

                            log.debug{"getCredential -> [!] WebWallet logs: JWT - ${jwt}"}

                            val test = "eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiUGVybWFuZW50UmVzaWRlbnRDYXJkIl0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9jaXRpemVuc2hpcC92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvYmJzL3YxIiwiaHR0cHM6Ly9zc2lwcm9qZWN0LmluZi51bS5lcy9zZWN1cml0eS9wc21zL3YxIl0sImlkIjoidXJuOnV1aWQ6NGVhNmVhYjUtMDE1MC00N2U0LThiMDEtOGUzNWE4ODJlYTMxIiwiaXNzdWVyIjoiZGlkOmtleXVtdTpYQkFlRk1zV3lQSHN1M3JUUFFKUFJ0VDNqUnM2azNBOFA0dVpNZXVIQXB6UWNZd1RSbjZIbUdrWDdCaHJQOUQ2OWpKVUNHTVdKS3l0bm5yV3hLeTRZNmpWaUVMM05ja0VyNktjcDhXYVpNQzVpWjlUekszcXFoQVUzc2FObXZXeFljOXNQUUtnekp4cjZick42RWRnWXlFVXRiQ1UzQkZhRm9nWm1uaWZGRGVzdWVzalhiWENFQkVUY3NubmRxWTV0WkxaVXRwY0NFeDRjeUJFNFpwSGNjMUJvZTE0WUp6Z2szNVAzYmliRGFoeTNUWmFOUkVKZEpHdkZhdGYzWnBTaU1lb1drUFp0cWNoamFkbllLWEVkNU56cGYzVURhbmkxZmlEWWlOYWt1N1V5YmhQQXUycm1rTGJVNHlTSlEyNUFad0pCOEJ6TEhyaXZ6bWhwYTRWZkdhbnBrN1FxTFZNQ0dtaU5zSGRwTGprWXNrRnZNR3RaQnI5TW1hVWFpTHRmdnhwNk5wVVhuVk01Q1haSGlQWXpUTHVUYzZidmdvTFBYWVp0TlpkYVBwQm9qZjZKZHR0OW4yUlNOQkN4U1RZa2Q0aHhCcDlUaHF2U1NDa3FyVjNRaGVIYURMTjg3dHJYM2txUEdlVVB0dVVtdGZnWjdSZWFHV1F6VHRzcFVrOVZKbjlZUFVzU3cxWkQ1dUJtVGszUHNkVGlqYkxVdWdQZ1VycjIxcnZRVVNUSjZKenFKdHY5Y3VEckt0Y2FkTVZFNnRFUXc2Z1htZmQ3OUg5QXlkSG5rRFlocW5YMlhHYm5EdWo2ejlTalhRNjNkZXlNYVIzNTF5QTV4ckV4M1pIZDRFWDNBUUVOWVpXRTd6V2JlM3RDc0poaUU3Tkt6d25YNkFlWGZyVnBKNlpBZWdvYmJmd1ZNc1ZaUzJTWW5aQzNUcXR0VUhCWmZHMVg5cFdZZENYVGtNM2ZVdkxEeXBLTHVUeFV0Nlpjb0Y5VkZVS0NGZGdRN0FVRGJNVHRVeHFtNDV0ektFYTlLQTVZTHlkaVlRYzd2VW1kMnBuQ2ttSFJ5WDhDaEZoUUthSjd1SGpOcXo5a21TN0ZjYjZXTVVTa1VFRWtBOXRBMWJiTThKckZnOWNmcGFiQ29GUVlUcnNtVWlqQlBLalFKa1BTOGFKc2NQQ25NMWM1RlVQdXRQdUVyQXlOQ0huUjFDRzR4aTd1c1FLUE1xMXhkcmhUaWh6VEJYYjZjRlFOWlFlNFpnOGhkSGV1TUt5TmJaWmlQUEZMY2NIM0J4SmlGazJlbm1HNDVVSDFwc2VqTVg2NERYTXZoQ3NxNlVHNUplZlM0bjRwNEx2ZWJtTENhWmlQazRtcU5yTTk2dW1WOFRvekFteDFtcWRSQ0NvOVlvcHh4UlJwc1lQQzRGR1NBNTRqUWRyaG5Sbzk1em1KWDZwWEpMRjFUNWV2dUJ1ZFh1eDg3QjJTVXgzYmRWTGl4WldVbk5vS1FpbkJ3UXhjTVN1ejNLQ1RKTWlOWUs3ZHhnWFE1UG9RU3pSeWJ3SmhaZ2ZIMjdHQ1JtQXN5eUhYNG5NV2ZoeTJHTVBxZENiM1RWSE11enhIbWZnd3pvUHZOc2RjRHh5eHhYbUVwZFk3RmFXaUZmdnFna3ZjdmRicEdEWXZ4Tk5WcW5nMlBKQ281Q3VQaGdaWVdOQ285UlZFaHBqMmlXd3BkdVNqVGV0TVFhczYyWGRlelRDckZ3c0dhNE5kb2o5Y3lzRUNBZVVMc0xhVVpYZGJTU0JLRWVlVlV0aTFjZ2ptN0x1Ykw2dHBlY2M0QXRSVjh1MURMaHU2b0xnUEZ4Z2pMMlhidDlvcE45SjduZG1aOGdNdmdCaERuNnNIb2RRc0I5WTdHb3BVZEtvdFZQVkdwMXR1Z05kaWdxTWRWU1RLa2lEOUxTSHY1QXc4Mk1UOFhwSlRhdFE4V3RkOUhZN0c0ejk2MWUzdENlbkgyQnp5SjJaQ0VNTjZ1elFvTnBNNWdCQjF6VnRUVXEzR0I5NFNUbUcxbjZwblEyb1l2OVdpd3J6RnlWbTF4cHRXZFFHWjJHYUtlVGN6d1VzbjZuQkp5aGpVQVVlSGRCSlNTU3ZURnpmViIsImlzc3VhbmNlRGF0ZSI6IjIwMjQtMDktMThUMTQ6Mjc6MDBaIiwiaXNzdWVkIjoiMjAyNC0wOS0xOFQxNDoyNzowMFoiLCJ2YWxpZEZyb20iOiIyMDI0LTA5LTE4VDE0OjI3OjAwWiIsInByb29mIjp7InR5cGUiOiJQc21zQmxzU2lnbmF0dXJlMjAyMiIsImNyZWF0b3IiOiJkaWQ6a2V5dW11OlhCQWVGTXNXeVBIc3UzclRQUUpQUnRUM2pSczZrM0E4UDR1Wk1ldUhBcHpRY1l3VFJuNkhtR2tYN0JoclA5RDY5akpVQ0dNV0pLeXRubnJXeEt5NFk2alZpRUwzTmNrRXI2S2NwOFdhWk1DNWlaOVR6SzNxcWhBVTNzYU5tdld4WWM5c1BRS2d6SnhyNmJyTjZFZGdZeUVVdGJDVTNCRmFGb2dabW5pZkZEZXN1ZXNqWGJYQ0VCRVRjc25uZHFZNXRaTFpVdHBjQ0V4NGN5QkU0WnBIY2MxQm9lMTRZSnpnazM1UDNiaWJEYWh5M1RaYU5SRUpkSkd2RmF0ZjNacFNpTWVvV2tQWnRxY2hqYWRuWUtYRWQ1TnpwZjNVRGFuaTFmaURZaU5ha3U3VXliaFBBdTJybWtMYlU0eVNKUTI1QVp3SkI4QnpMSHJpdnptaHBhNFZmR2FucGs3UXFMVk1DR21pTnNIZHBMamtZc2tGdk1HdFpCcjlNbWFVYWlMdGZ2eHA2TnBVWG5WTTVDWFpIaVBZelRMdVRjNmJ2Z29MUFhZWnROWmRhUHBCb2pmNkpkdHQ5bjJSU05CQ3hTVFlrZDRoeEJwOVRocXZTU0NrcXJWM1FoZUhhRExOODd0clgza3FQR2VVUHR1VW10ZmdaN1JlYUdXUXpUdHNwVWs5VkpuOVlQVXNTdzFaRDV1Qm1UazNQc2RUaWpiTFV1Z1BnVXJyMjFydlFVU1RKNkp6cUp0djljdURyS3RjYWRNVkU2dEVRdzZnWG1mZDc5SDlBeWRIbmtEWWhxblgyWEdibkR1ajZ6OVNqWFE2M2RleU1hUjM1MXlBNXhyRXgzWkhkNEVYM0FRRU5ZWldFN3pXYmUzdENzSmhpRTdOS3p3blg2QWVYZnJWcEo2WkFlZ29iYmZ3Vk1zVlpTMlNZblpDM1RxdHRVSEJaZkcxWDlwV1lkQ1hUa00zZlV2TER5cEtMdVR4VXQ2WmNvRjlWRlVLQ0ZkZ1E3QVVEYk1UdFV4cW00NXR6S0VhOUtBNVlMeWRpWVFjN3ZVbWQycG5Da21IUnlYOENoRmhRS2FKN3VIak5xejlrbVM3RmNiNldNVVNrVUVFa0E5dEExYmJNOEpyRmc5Y2ZwYWJDb0ZRWVRyc21VaWpCUEtqUUprUFM4YUpzY1BDbk0xYzVGVVB1dFB1RXJBeU5DSG5SMUNHNHhpN3VzUUtQTXExeGRyaFRpaHpUQlhiNmNGUU5aUWU0Wmc4aGRIZXVNS3lOYlpaaVBQRkxjY0gzQnhKaUZrMmVubUc0NVVIMXBzZWpNWDY0RFhNdmhDc3E2VUc1SmVmUzRuNHA0THZlYm1MQ2FaaVBrNG1xTnJNOTZ1bVY4VG96QW14MW1xZFJDQ285WW9weHhSUnBzWVBDNEZHU0E1NGpRZHJoblJvOTV6bUpYNnBYSkxGMVQ1ZXZ1QnVkWHV4ODdCMlNVeDNiZFZMaXhaV1VuTm9LUWluQndReGNNU3V6M0tDVEpNaU5ZSzdkeGdYUTVQb1FTelJ5YndKaFpnZkgyN0dDUm1Bc3l5SFg0bk1XZmh5MkdNUHFkQ2IzVFZITXV6eEhtZmd3em9Qdk5zZGNEeHl4eFhtRXBkWTdGYVdpRmZ2cWdrdmN2ZGJwR0RZdnhOTlZxbmcyUEpDbzVDdVBoZ1pZV05DbzlSVkVocGoyaVd3cGR1U2pUZXRNUWFzNjJYZGV6VENyRndzR2E0TmRvajljeXNFQ0FlVUxzTGFVWlhkYlNTQktFZWVWVXRpMWNnam03THViTDZ0cGVjYzRBdFJWOHUxRExodTZvTGdQRnhnakwyWGJ0OW9wTjlKN25kbVo4Z012Z0JoRG42c0hvZFFzQjlZN0dvcFVkS290VlBWR3AxdHVnTmRpZ3FNZFZTVEtraUQ5TFNIdjVBdzgyTVQ4WHBKVGF0UThXdGQ5SFk3RzR6OTYxZTN0Q2VuSDJCenlKMlpDRU1ONnV6UW9OcE01Z0JCMXpWdFRVcTNHQjk0U1RtRzFuNnBuUTJvWXY5V2l3cnpGeVZtMXhwdFdkUUdaMkdhS2VUY3p3VXNuNm5CSnloalVBVWVIZEJKU1NTdlRGemZWIiwiY3JlYXRlZCI6IjIwMjQtMDktMThUMTQ6Mjc6MDBaIiwicHJvb2ZQdXJwb3NlIjoiYXNzZXJ0aW9uTWV0aG9kIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOmtleXVtdTpYQkFlRk1zV3lQSHN1M3JUUFFKUFJ0VDNqUnM2azNBOFA0dVpNZXVIQXB6UWNZd1RSbjZIbUdrWDdCaHJQOUQ2OWpKVUNHTVdKS3l0bm5yV3hLeTRZNmpWaUVMM05ja0VyNktjcDhXYVpNQzVpWjlUekszcXFoQVUzc2FObXZXeFljOXNQUUtnekp4cjZick42RWRnWXlFVXRiQ1UzQkZhRm9nWm1uaWZGRGVzdWVzalhiWENFQkVUY3NubmRxWTV0WkxaVXRwY0NFeDRjeUJFNFpwSGNjMUJvZTE0WUp6Z2szNVAzYmliRGFoeTNUWmFOUkVKZEpHdkZhdGYzWnBTaU1lb1drUFp0cWNoamFkbllLWEVkNU56cGYzVURhbmkxZmlEWWlOYWt1N1V5YmhQQXUycm1rTGJVNHlTSlEyNUFad0pCOEJ6TEhyaXZ6bWhwYTRWZkdhbnBrN1FxTFZNQ0dtaU5zSGRwTGprWXNrRnZNR3RaQnI5TW1hVWFpTHRmdnhwNk5wVVhuVk01Q1haSGlQWXpUTHVUYzZidmdvTFBYWVp0TlpkYVBwQm9qZjZKZHR0OW4yUlNOQkN4U1RZa2Q0aHhCcDlUaHF2U1NDa3FyVjNRaGVIYURMTjg3dHJYM2txUEdlVVB0dVVtdGZnWjdSZWFHV1F6VHRzcFVrOVZKbjlZUFVzU3cxWkQ1dUJtVGszUHNkVGlqYkxVdWdQZ1VycjIxcnZRVVNUSjZKenFKdHY5Y3VEckt0Y2FkTVZFNnRFUXc2Z1htZmQ3OUg5QXlkSG5rRFlocW5YMlhHYm5EdWo2ejlTalhRNjNkZXlNYVIzNTF5QTV4ckV4M1pIZDRFWDNBUUVOWVpXRTd6V2JlM3RDc0poaUU3Tkt6d25YNkFlWGZyVnBKNlpBZWdvYmJmd1ZNc1ZaUzJTWW5aQzNUcXR0VUhCWmZHMVg5cFdZZENYVGtNM2ZVdkxEeXBLTHVUeFV0Nlpjb0Y5VkZVS0NGZGdRN0FVRGJNVHRVeHFtNDV0ektFYTlLQTVZTHlkaVlRYzd2VW1kMnBuQ2ttSFJ5WDhDaEZoUUthSjd1SGpOcXo5a21TN0ZjYjZXTVVTa1VFRWtBOXRBMWJiTThKckZnOWNmcGFiQ29GUVlUcnNtVWlqQlBLalFKa1BTOGFKc2NQQ25NMWM1RlVQdXRQdUVyQXlOQ0huUjFDRzR4aTd1c1FLUE1xMXhkcmhUaWh6VEJYYjZjRlFOWlFlNFpnOGhkSGV1TUt5TmJaWmlQUEZMY2NIM0J4SmlGazJlbm1HNDVVSDFwc2VqTVg2NERYTXZoQ3NxNlVHNUplZlM0bjRwNEx2ZWJtTENhWmlQazRtcU5yTTk2dW1WOFRvekFteDFtcWRSQ0NvOVlvcHh4UlJwc1lQQzRGR1NBNTRqUWRyaG5Sbzk1em1KWDZwWEpMRjFUNWV2dUJ1ZFh1eDg3QjJTVXgzYmRWTGl4WldVbk5vS1FpbkJ3UXhjTVN1ejNLQ1RKTWlOWUs3ZHhnWFE1UG9RU3pSeWJ3SmhaZ2ZIMjdHQ1JtQXN5eUhYNG5NV2ZoeTJHTVBxZENiM1RWSE11enhIbWZnd3pvUHZOc2RjRHh5eHhYbUVwZFk3RmFXaUZmdnFna3ZjdmRicEdEWXZ4Tk5WcW5nMlBKQ281Q3VQaGdaWVdOQ285UlZFaHBqMmlXd3BkdVNqVGV0TVFhczYyWGRlelRDckZ3c0dhNE5kb2o5Y3lzRUNBZVVMc0xhVVpYZGJTU0JLRWVlVlV0aTFjZ2ptN0x1Ykw2dHBlY2M0QXRSVjh1MURMaHU2b0xnUEZ4Z2pMMlhidDlvcE45SjduZG1aOGdNdmdCaERuNnNIb2RRc0I5WTdHb3BVZEtvdFZQVkdwMXR1Z05kaWdxTWRWU1RLa2lEOUxTSHY1QXc4Mk1UOFhwSlRhdFE4V3RkOUhZN0c0ejk2MWUzdENlbkgyQnp5SjJaQ0VNTjZ1elFvTnBNNWdCQjF6VnRUVXEzR0I5NFNUbUcxbjZwblEyb1l2OVdpd3J6RnlWbTF4cHRXZFFHWjJHYUtlVGN6d1VzbjZuQkp5aGpVQVVlSGRCSlNTU3ZURnpmViNiN2JjMjhjODY1MDg0NTc5YWU2M2E3NTVmZGVmNTRmNCIsInByb29mVmFsdWUiOiJ6UXV4RllWRWdIdVdmWjd5TG9HSlhMbUZoV0dVcll4THZaQ0tyREJOYXpnSHBFaE51YTdOd3E0cnhWdkQ0RnZKQUZEQ1lwUFJwU2pFanJyZmt0a1BiUlhGalJSak43RzIzaWo1alk3MVdpYkVqNEI2YUo5aU5oUkI5ZTdLdkVxaTVneHZLb3VhUWtvc3dDRlhRYTZFQVpFeDZCS3AzYTVzZ01VZ1dOWVNYVUJXQU5KZ2QzWjVCQTF4M3N4ajZUdHpDOXBHWlNod1V4aUpSRGtqV1NtZDc2YmtMOHZSQkdkdmJKNWFXNlRhYW1ZcU5xZ2Z0RTFYYlp5WGdLQVpxWG1yam9LN05oRWNIYmVjaUU4SFlQSkc2aHBQS2dEdHhhSlFRMjI2QnU5N2huazFSTU5EdDVnRGtua0FoWXAzRjJBeDhwblhONFI0UjhkVFJISzVKUXNtTkVWZ1F3UjdxNVM4OFVIYUFwRmRyTWJYV1VyRjNwRG5BUlFhTUNwcGRHaHpKWUZTd1NhTGZQYjl3bjZvMUdyWEFlNXYxdjQ1WXhMUnVacTJ6Q1BSSmVXZ3RUaGJCajlONnJUeVRXQWtLcWFRSExOUkRoM25ob0tjYWsxY3Z2TmVFeGNmQ2pmVjZZamhuNmRHcHkzVHpxSFZpbXRzS1J3MkVDRWZEcVhYZ2h0SDlna29WOGppd1BXNWtucmVGQjRZTEV4NkhqRmpHbjczRTVrMjZmYTNZQ3hvaTZ2Z2I0Z1ZMOWFKMmY5NUZyTVpyZGc5a2tITkxEMVl5c0RhZVg4NGhzS2V2RG1uRDJpa2pZbnpBdmt2bkNnS1hFdnRaMzFqbTdWTUt5aGRRVmVTOUV6Q01pTmd3c3o4emRxQVhaOVR1amtGNDd4VzZSdUNOZG0yS1hNQXdEOXVtTHZGcXVla0NEZzF2NlBXUnZLc0hTcXh0cnlCdjJ0QmpzZVkya1ZyWGZNWm9xSnNja21hUDlTWmhiZnk0UE5oanFSVDI1TUJTIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rcGVtWGlEbmhaRVpYWThtTmtOOEVlamloZGphc3YxbTlrWVVYS1JicWkzbTgiLCJ0eXBlIjoiUGVybWFuZW50UmVzaWRlbnQiLCJnaXZlbk5hbWUiOiJQZWRybyIsImZhbWlseU5hbWUiOiJKYW4iLCJnZW5kZXIiOiJNYWxlIiwiYmlydGhEYXRlIjoiMTk5OC0xMi0wOSIsImJpcnRoQ291bnRyeSI6IlNwYWluIn0sIm5hbWUiOiJwZWRybyIsImFsZyI6IkhTMjU2In0"
                            call.respond(test)
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
