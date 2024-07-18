package id.walt.model.oidc

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.services.did.DidService
import id.walt.services.jwt.JwtService
import id.walt.services.keystore.KeyStoreService
import java.time.Instant
import java.util.*

data class SelfIssuedIDTokenUmu(
    val subject: String,
    val issuer: String,
    val client_id: String?,
    val nonce: String?,
    val expiration: Instant?,
    val issueDate: Instant? = Instant.now(),
    val requester: String?,
    val method: String?,
    val url: String?,
    // legacy OIDC4VP spec, including presentation submission in _vp_token JWT claim of id_token (used by EBSI conformance v2)
    val _vp_token: VpTokenRef? = null,
    val keyId: String? = null
) {
    fun sign(): String {
        val builder = JWTClaimsSet.Builder().subject(subject).issuer(issuer)
        client_id?.let { builder.audience(it) }
        nonce?.let { builder.claim("nonce", it) }
        expiration?.let { builder.expirationTime(Date.from(expiration)) }
        issueDate?.let { builder.issueTime(Date.from(issueDate)) }
        requester?.let {builder.claim("requester", it) }
        method?.let {builder.claim("method", it) } 
        url?.let {builder.claim("url", it) } 
        _vp_token?.let { builder.claim("_vp_token", it) }

        if (keyId != null){
            return JwtService.getService().sign(
                keyId,
                builder.build().toString()
            )
        }
        
        return JwtService.getService().sign(
            issuer,
            builder.build().toString()
        )
    }

    companion object {
        fun parse(jwt: String): SelfIssuedIDTokenUmu? {
            val parsedJWT = SignedJWT.parse(jwt) ?: return null
            return SelfIssuedIDTokenUmu(
                subject = parsedJWT.jwtClaimsSet.subject,
                issuer = parsedJWT.jwtClaimsSet.getStringClaim("issuer"),
                client_id = parsedJWT.jwtClaimsSet.audience?.firstOrNull(),
                nonce = parsedJWT.jwtClaimsSet.getStringClaim("nonce"),
                expiration = parsedJWT.jwtClaimsSet.expirationTime?.toInstant(),
                issueDate = parsedJWT.jwtClaimsSet.issueTime?.toInstant(),
                requester = parsedJWT.jwtClaimsSet.getStringClaim("requester"),
                method = parsedJWT.jwtClaimsSet.getStringClaim("method"),
                url = parsedJWT.jwtClaimsSet.getStringClaim("url")
            )
        }

        fun verify(jwt: String): Boolean {
            val parsedToken = parse(jwt) ?: return false
            if (KeyStoreService.getService().getKeyId(parsedToken.subject) == null) {
                DidService.importKeys(parsedToken.subject)
            }
            return JwtService.getService().verify(jwt).verified
        }
    }
}
