document.addEventListener('DOMContentLoaded', function () {
    const createCredentialBtn = document.getElementById('createCredential');
    const modal = document.getElementById('modal');
    const closeButton = document.querySelector('.close-button');
    const credentialList = document.getElementById('credentialList');

    // Función para cerrar el modal
    closeButton.addEventListener('click', function() {
        modal.style.display = 'none';
    });

    // Función para manejar solicitud de credenciales
    function fetchCredentials(url) {
        fetch(url, {
            method: 'GET',
            credentials: 'include'
        })
                .then(response => {
                    let content = response.text()
                    console.log(response)
                    if (!response.ok) {
                        content.then(text => {
                            if (text.startsWith("Error:")) {
                                const errorMessage = text.substring(6).trim();
                                window.location.href = `/wallet/error?error=${encodeURIComponent(errorMessage)}`;
                            }
                            // Lanza un error si no es un mensaje de error formateado
                            throw new Error(text);
                        });
                    }
                    return content
                })
                .then(text => {
                    let data;
                    try {
                        data = JSON.parse(text); // Intentar parsear el texto como JSON
                    } catch (error) {
                        console.error('Error parsing JSON:', error);
                        throw new Error('Invalid JSON format');
                    }
                    return data;
                })
                .then(data => {
                    credentialList.innerHTML = ''; // Limpiar la lista existente
                    data.forEach(credential => {
                        const listItem = document.createElement('li');
                        listItem.textContent = credential;
                        listItem.onclick = function() {
                            fetch('/wallet/credentialParameters', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded'
                                },
                                credentials: 'include',
                                body: new URLSearchParams({ credentialId: credential }).toString()
                            })
                                    .then(response => {
                                        if (!response.ok) {
                                            throw new Error('Error fetching example');
                                        }
                                        return response.text();
                                    })
                                    .then(url => {
                                        window.location.href = url; // Redirigir al usuario a la nueva URL
                                    });
                        };
                        credentialList.appendChild(listItem); // Agregar el elemento a la lista
                    });
                    modal.style.display = 'block'; // Mostrar el modal
                })
                .catch(error => {
                    console.error('Error:', error);
                });
    }


    createCredentialBtn.addEventListener('click', function() {
        fetchCredentials('/wallet/list-credentials');
    });

    const listCredsButton = document.getElementById('ListCreds');
    listCredsButton.addEventListener('click', function() {
        window.location.href = '/wallet/credentials';
    });

    const checkMetadataButton = document.getElementById('CheckMetadata');
    checkMetadataButton.addEventListener('click', function() {
        window.location.href = '/wallet/Configuration';
    });
});
