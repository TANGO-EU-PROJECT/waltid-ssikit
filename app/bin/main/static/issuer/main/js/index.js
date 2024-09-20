document.getElementById('api-endpoint').addEventListener('input', function () {
    generateQRCode();
});

document.getElementById('send-request').addEventListener('click', async function () {
    const endpoint = document.getElementById('api-endpoint').value;
    const protocol = window.location.protocol;
    const hostname = window.location.hostname;
    const port = window.location.port;
    const credentialOfferUri = `${protocol}//${hostname}${port ? `:${port}` : ''}/issuer/CredentialOffer`;

    console.log(endpoint)
    let params = new URLSearchParams({
        credential_offer_uri: credentialOfferUri
    });

    const cookies = {
        clientId: document.cookie.split('; ').find(row => row.startsWith('clientId-umu-issuer='))?.split('=')[1],
        clientSecret: document.cookie.split('; ').find(row => row.startsWith('clientSecret-umu-issuer='))?.split('=')[1]
    };

    if (cookies.clientId) {
        params.append('clientid', cookies.clientId);
    }

    if (cookies.clientSecret) {
        params.append('clientsecret', cookies.clientSecret);
    }

    const fullUrl = `${endpoint}/openid-credential-offer?${params.toString()}`;

    try {
        const response = await axios.get(fullUrl);
        console.log('Response:', response.data);
        const validUrlPattern = /^(https?:\/\/)?([\da-z.-]+)(:[\d]{1,5})?([\/\w .-]*)*\/?$/;
        if (response.data.startsWith('http')) {
            window.location.href = response.data; // Hacer redirect si la respuesta comienza con 'http'.
        } else {
            console.error('La respuesta no comienza con "http":', response.data);
        }

    } catch (error) {
        console.error('Error:', error);
    }
});

function generateQRCode() {
    const protocol = window.location.protocol;
    const hostname = window.location.hostname;
    const port = window.location.port;
    const credentialOfferUri = `${protocol}//${hostname}${port ? `:${port}` : ''}/issuer/CredentialOffer`;
    const cookies = {
        clientId: document.cookie.split('; ').find(row => row.startsWith('clientId-umu-issuer='))?.split('=')[1],
        clientSecret: document.cookie.split('; ').find(row => row.startsWith('clientSecret-umu-issuer='))?.split('=')[1]
    };

    const qrContent = `credential_offer_uri=${credentialOfferUri}&clientid=${cookies.clientId}&clientsecret=${cookies.clientSecret}`;
    document.getElementById("qrcode").innerHTML = ""; // Clear previous QR code
    new QRCode(document.getElementById("qrcode"), qrContent);
}

// Inicializa el QR code al cargar la página
generateQRCode();
