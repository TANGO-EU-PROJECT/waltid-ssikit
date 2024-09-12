{
    "assertionMethod" : [
        "did:web:example.com#0e2ab01482ba44aa8be319efad93adca"
    ],
    "authentication" : [
        "did:web:example.com#0e2ab01482ba44aa8be319efad93adca"
    ],
    "@context" : "https://www.w3.org/ns/did/v1",
    "id" : "did:web:example.com",
    "verificationMethod" : [
        {
            "controller" : "did:web:example.com",
            "id" : "did:web:example.com#0e2ab01482ba44aa8be319efad93adca",
            "publicKeyJwk" : {
                "alg" : "EdDSA",
                "crv" : "Ed25519",
                "kid" : "0e2ab01482ba44aa8be319efad93adca",
                "kty" : "OKP",
                "use" : "sig",
                "x" : "ZNXZyJsqnpEmSP2MYHrcbGZjh6xATBeRWcmqY8bOHI8"
            },
            "type" : "Ed25519VerificationKey2019"
        }
    ]
}