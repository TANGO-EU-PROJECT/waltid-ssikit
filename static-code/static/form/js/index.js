document.addEventListener('DOMContentLoaded', function() {
    // Extracción de parámetros de la URL
    const urlParams = new URLSearchParams(window.location.search);
    const templateName = urlParams.get('template');

    if (templateName) {
        // Asumimos que el archivo JSON está en la carpeta 'templates' y su nombre coincide con 'templateName'
        fetch(`/static/form/templates/${templateName}.json`)
            .then(response => response.json())
            .then(data => {
                buildForm(data, templateName);
            })
            .catch(error => {
                console.error('Error al cargar la plantilla:', error);
                displayMessage('Error al cargar la plantilla. Por favor, revise la consola para más detalles.');
            });
    }

    function checkSession() {
        const clientIdCookie = document.cookie.split('; ').find(row => row.startsWith('clientId-umu-issuer='));
        const clientSecretCookie = document.cookie.split('; ').find(row => row.startsWith('clientSecret-umu-issuer='));

        if (!clientIdCookie || !clientSecretCookie) {
            window.location.href = `https://umu-webWallet:<WALLET_PORT>/login`;
        } 
    }
    
});

function buildForm(template, templateName) {
    const clientIdCookie = document.cookie
        .split('; ')
        .find(row => row.startsWith('clientId-umu-issuer='))
        .split('=')[1]; 

    const clientSecretCookie = document.cookie
        .split('; ')
        .find(row => row.startsWith('clientSecret-umu-issuer='))
        .split('=')[1]; 

    const formContainer = document.getElementById('dynamicForm');
    formContainer.innerHTML = ''; // Limpia el contenedor del formulario

    const form = document.createElement('form');
    form.onsubmit = function(event) {
        event.preventDefault(); // Evita el comportamiento por defecto del formulario

        let userData = {};
        Object.keys(template.credentialSubject).forEach(key => {
            userData[key] = form[key].value;
        });



        // Envía la solicitud POST al endpoint de la API
        fetch('https://umu-webWallet:<WALLET_PORT>/createCredential', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientId: clientIdCookie,
                clientSecret: clientSecretCookie,
                type: templateName,
                template: userData 
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.text();
        })
        .then(data => {
            showModal(data)
        })
        .catch(error => {
            console.error('Error durante la solicitud POST:', error);
            displayMessage('Error durante la solicitud POST. Por favor, revise la consola para más detalles.');
        });
    };

    // Creación dinámica del formulario basado en la plantilla JSON
    Object.keys(template.credentialSubject).forEach(key => {
        const inputGroup = document.createElement('div');
        inputGroup.classList.add('input-group');

        const label = document.createElement('label');
        label.setAttribute('for', key);
        label.textContent = key;
        inputGroup.appendChild(label);

        const input = document.createElement('input');
        input.setAttribute('type', 'text');
        input.setAttribute('name', key);
        input.setAttribute('id', key); // Asegúrate de que el 'id' y el 'for' del label coincidan
        inputGroup.appendChild(input);

        form.appendChild(inputGroup);
    });

    const submitButton = document.createElement('input');
    submitButton.setAttribute('type', 'submit');
    submitButton.setAttribute('value', 'Enviar');
    form.appendChild(submitButton);

    formContainer.appendChild(form);
}

function displayMessage(message) {
    // Busca un contenedor de mensajes existente o crea uno nuevo si no existe
    let messageContainer = document.getElementById('messageContainer');
    if (!messageContainer) {
        messageContainer = document.createElement('div');
        messageContainer.setAttribute('id', 'messageContainer');
        document.body.appendChild(messageContainer);
    }
    
    // Actualiza el contenido del contenedor de mensajes
    messageContainer.textContent = message;
}
function showModal(credential) {
    const prettyCredential = JSON.stringify(credential, null, 2)
      .replace(/\\n/g, '\n')
      .replace(/\\"/g, '"');
  
    // Crear el modal
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <h2>Credential Details</h2>
        <div class="credential-body">
          <pre>${prettyCredential}</pre>
        </div>
        <input type="text" class="form-control" id="credentialName" aria-label="Credential Name" aria-describedby="credential-name-label">
        <div class="modal-buttons">
          <button id="saveButton">Guardar</button>
          <button onclick="discardCredential()">Descartar</button>
        </div>
      </div>
    `;
  
    // Añadir el modal al cuerpo del documento
    document.body.appendChild(modal);
  
    // Añadir evento de clic al botón de guardar
    document.getElementById('saveButton').onclick = function() {
        const credentialName = document.getElementById('credentialName').value; 
      saveCredential(credential, credentialName);
    };
  }
  
  // Función para guardar la credencial
  function saveCredential(credential, credentialName) {

    closeModal();

    let jsonObject = JSON.parse(credential);

    // Añadimos la propiedad "name" con el valor proporcionado
    jsonObject["name"] = credentialName;
  
    // Convertimos el objeto modificado a un string JSON
    let credential2 = JSON.stringify(jsonObject);


        const formData = new FormData();
        formData.append('credential', credential2);
        formData.append('nameCred', credentialName);
        
    fetch('https://umu-webWallet:<WALLET_PORT>/storeCredential', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text()) 
    .then(text => {
        console.log(text); 
        window.location.href = "https://umu-webWallet:<WALLET_PORT>/demo";
        //window.location.href = "/"; 
    })
    .catch(error => {
        console.error('Error:', error);
    });
    
    
  }
  
  // Función para descartar la credencial y cerrar el modal
  function discardCredential() {
    closeModal();
  }
  
  // Función para cerrar el modal
  function closeModal() {
    const modal = document.querySelector('.modal');
    if (modal) {
      modal.remove();
    }
  }
