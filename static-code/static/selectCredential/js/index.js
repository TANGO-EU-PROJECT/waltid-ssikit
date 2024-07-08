// script.js
document.addEventListener('DOMContentLoaded', function () {
    const credentialList = document.getElementById('credentialList');

    // Ejecuta la solicitud de credenciales automáticamente
    const clientIdCookie = document.cookie.split('; ').find(row => row.startsWith('clientId-umu-issuer='));
    const clientSecretCookie = document.cookie.split('; ').find(row => row.startsWith('clientSecret-umu-issuer='));

    if (!clientIdCookie || !clientSecretCookie) {
        // Si no hay cookies de sesión, redirigir al usuario
        window.location.href = 'https://umu-webWallet:<WALLET_PORT>/login';
    } else {
        fetch('https://umu-webWallet:<WALLET_PORT>/metadata', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            credentials: 'include',
            body: new URLSearchParams({
                issuer: 'https://umu-issuer:<ISSUER_PORT>/list'
            }).toString()
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Error fetching metadata');
            }
            return response.text();
        })
        .then(data => {
            const parsedData = data.slice(1, -1).split(', '); // Parsear el string para obtener un array
            credentialList.innerHTML = ''; // Limpiar la lista anterior
        
            parsedData.forEach(credential => {
                const listItem = document.createElement('li');
                listItem.textContent = credential.trim();
                listItem.onclick = function() { 

                    const clientIdCookie = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('clientId-umu-issuer='))
                    .split('=')[1]; 

                    fetch('https://umu-webWallet:<WALLET_PORT>/credentialParameters', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        credentials: 'include',
                        body: new URLSearchParams({
                            template: credential.trim(),
                            clientId: clientIdCookie
                        }).toString()
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('Error fetching metadata');
                        }
                        return response.text();
                    })
                    .then(data => {
                        window.location.href = data;
                    })
                    
                };
                
                
                credentialList.appendChild(listItem);
            });
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
});
