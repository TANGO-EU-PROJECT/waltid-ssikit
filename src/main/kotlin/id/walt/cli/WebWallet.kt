package id.walt.cli

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.ktor.server.http.content.*
import kotlinx.coroutines.runBlocking
import com.github.ajalt.clikt.core.CliktCommand
import org.slf4j.LoggerFactory
import java.io.File


/* SSIKIT issuer */
class WebWallet :
        CliktCommand(
                name = "web-wallet",
                help = "Start web wallet"
        ) {
    override fun run() {
        runBlocking {
            val environment = applicationEngineEnvironment {
                log = LoggerFactory.getLogger("ktor.application")
                connector {
                    port = 8100 // Usar solo el puerto para HTTP
                }
                module {
                    routing {
                        static("/") {
                            resources("static")
                            defaultResource("index.html", "static")

                        }

                        get("/") {
                            println("test")

                        }
                    }

                }
            }

            embeddedServer(Netty, environment).start(wait = true)
        }
    }
}

fun main() {
    WebWallet().main(arrayOf())
}
