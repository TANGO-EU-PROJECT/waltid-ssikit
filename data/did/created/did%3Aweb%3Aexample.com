{
    "assertionMethod" : [
        "did:web:example.com#84ed73e42d7a4025a670c664cc846f08"
    ],
    "authentication" : [
        "did:web:example.com#84ed73e42d7a4025a670c664cc846f08"
    ],
    "@context" : "https://www.w3.org/ns/did/v1",
    "id" : "did:web:example.com",
    "verificationMethod" : [
        {
            "controller" : "did:web:example.com",
            "id" : "did:web:example.com#84ed73e42d7a4025a670c664cc846f08",
            "publicKeyJwk" : {
                "alg" : "EdDSA",
                "crv" : "Ed25519",
                "kid" : "84ed73e42d7a4025a670c664cc846f08",
                "kty" : "OKP",
                "use" : "sig",
                "x" : "d8pAbJkq4l91liJw-xIuJt2kQoAZcWvGFgw5QI_ufjI"
            },
            "type" : "Ed25519VerificationKey2019"
        }
    ]
}