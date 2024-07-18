document.addEventListener('DOMContentLoaded', function () {
    const createCredentialBtn = document.getElementById('createCredential');
    const completeVerificationBtn = document.getElementById('completeVerification');
    const sessionStatus = document.getElementById('sessionStatus');
    const modal = document.getElementById('modal');
    const closeButton = document.querySelector('.close-button');
    const credentialList = document.getElementById('credentialList');

    // Función para cerrar el modal
    closeButton.addEventListener('click', function() {
        modal.style.display = 'none';
    });

    // Función para comprobar las cookies de sesión
    function checkSession() {
        const clientIdCookie = document.cookie.split('; ').find(row => row.startsWith('clientId-umu-issuer='));
        const clientSecretCookie = document.cookie.split('; ').find(row => row.startsWith('clientSecret-umu-issuer='));

        if (!clientIdCookie || !clientSecretCookie) {
            sessionStatus.textContent = 'You are not logged in to the credential issuer.';
        } else {
            sessionStatus.textContent = 'You are logged in to the credential issuer.';
        }
    }

    // Evento para el botón "Create Credential"
    createCredentialBtn.addEventListener('click', function() {

        const clientIdCookie = document.cookie.split('; ').find(row => row.startsWith('clientId-umu-issuer='));
        const clientSecretCookie = document.cookie.split('; ').find(row => row.startsWith('clientSecret-umu-issuer='));

        if (!clientIdCookie || !clientSecretCookie) {
            // Si no hay cookies de sesión, redirigir al usuario
            window.location.href = 'https://umu-webWallet:8445/login';
        } else {

            fetch('https://umu-webWallet:8445/metadata', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                credentials: 'include',
                body: new URLSearchParams({
                    issuer: 'https://umu-issuer:8443/list'
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

                        fetch('https://umu-webWallet:8445/credentialParameters', {
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
                
                modal.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }
    });

    // Evento para el botón "Complete Verification"
    completeVerificationBtn.addEventListener('click', function() {
        alert('Complete the verification process.');
    });

    checkSession(); // Comprobar la sesión al cargar la página
});

// Función para borrar todas las cookies
function clearCookies() {
    // Obtener todas las cookies del documento
    const cookies = document.cookie.split(";");
  
    // Para cada cookie, establecer su fecha de expiración en el pasado
    for (let cookie of cookies) {
      const eqPos = cookie.indexOf("=");
      const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
      document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
    }
  }
  
  // Función para manejar el evento de clic en el botón de Log Out
  function handleLogOut() {
    clearCookies(); // Llama a la función para borrar las cookies
    window.location.reload(); // Recarga la página
  }
  
  document.addEventListener('DOMContentLoaded', (event) => {
    const logOutButton = document.getElementById('LogOut');
    if (logOutButton) {
      logOutButton.addEventListener('click', handleLogOut);
    }
  });

  function handleListCred() {
    window.location.href = "/credentials"
  }

  document.addEventListener('DOMContentLoaded', (event) => {
    const lListCredsButton = document.getElementById('ListCreds');
    if (lListCredsButton) {
        lListCredsButton.addEventListener('click', handleListCred);
    }
  });
  