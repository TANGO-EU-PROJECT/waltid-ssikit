document.addEventListener('DOMContentLoaded', function() {
    fetchCredentials();
  });

  function parseCredentialString(inputString) {
    // Dividir el string de entrada en partes usando los corchetes como separadores
    const parts = inputString.match(/\[(.*?)\]/g).map(part => part.replace(/[\[\]]/g, ''));
  
    // Extraer la información relevante de las partes
    const credentialTypes = parts[0].split(', ');
    const fields = parts[1].split(', ');
    const values = parts[2].split(', ');
  
    // Comenzar a construir el mensaje de salida
    let message = 'La política requerida indica que la credencial tiene que ser de tipo ';
    message += credentialTypes.join(', ') + ', además de incluir los siguientes valores:\n\n';
  
    // Añadir los campos y sus valores al mensaje
    fields.forEach((field, index) => {
      message += `En el campo "${field.slice(field.lastIndexOf('.') + 1)}": ${values[index]}\n`;
    });
  
    return message;
  }
  
  function fetchCredentials() {
    fetch('https://umu-webWallet:30002/vpTokenDetails')
      .then(response => response.text())
      .then(result => {
        const outputText = parseCredentialString(result)
        document.getElementById('text-output').innerText = outputText;
      })
      .catch(error => {
        console.error('Error fetching credentials:', error);
      });

    fetch('https://umu-webWallet:30002/validCredentials')
      .then(response => response.json())
      .then(credentials => {
        displayCredentials(credentials);
      })
      .catch(error => {
        console.error('Error fetching credentials:', error);
      });
  }
  
  function displayCredentials(credentials) {
    const container = document.getElementById('credentials-container');
    // Asegúrate de que el contenedor esté vacío antes de agregar nuevos elementos
    container.innerHTML = '';

    if (Object.keys(credentials).length === 0) {
      showModal("No hay credenciales que cumplen la política");
    }
    
    Object.entries(credentials).forEach(([id, credentialArray]) => {
      credentialArray.forEach(credential => {
        const div = document.createElement('div');
        div.textContent = `Credential: ${credential.name}`;
        div.className = 'credential-item'; // Añade una clase para estilizar
        div.onclick = () => openModal(credential);
        container.appendChild(div);
      });
    });
  }

  function showModal(message) {
    const modal = document.getElementById('credential-modal');
    const details = document.getElementById('credential-details');
    details.textContent = message;
  
    const emitButton = document.createElement('button');
    emitButton.textContent = 'Comenzar proceso de emisión';
    emitButton.id = 'emit-button';
    emitButton.onclick = function() {
      window.location.href = `https://umu-webWallet:30002/selectCredential?redirecturi=/verifyCredential`;
    };
  
    // Agrega el botón solo si aún no existe
    if (!document.querySelector('#emit-button')) {
      const modalContent = document.getElementById('modal-content');
      modalContent.appendChild(emitButton);
    }
  
    modal.style.display = 'block';
  }
  
  
  function openModal(credential) {
    const modal = document.getElementById('credential-modal');
    const details = document.getElementById('credential-details');
    const modalcontent = document.getElementById('modal-content');
    
    // Assuming `credential` is an object with `id`, `name`, and other properties
    details.textContent = JSON.stringify(credential, null, 2);
    
    // Check if the select button already exists
    let selectButton = modal.querySelector('#select-button');
    if (!selectButton) {
      // Create the select button if it doesn't exist
      selectButton = document.createElement('button');
      selectButton.id = 'select-button';
      selectButton.textContent = 'select';
      
      // Add click event listener to the button
      selectButton.onclick = function() {
        selectCredential(JSON.stringify(credential, null, 2));
      };
      
      // Append the button to the modal
      modalcontent.appendChild(selectButton);
    }
    
    // Display the modal
    modal.style.display = 'block';
  }
  
  function selectCredential(credential) {
    console.log(credential);

    fetch('https://umu-webWallet:30002/selectCredential', {
        method: 'POST',
        headers: {
            'Content-Type': 'text/plain', 
        },
        body: credential 
    })
    .then(response => response.text()) 
    .then(text => {
      window.location.href = `https://umu-verifier:30001/verify?TokenJWT=${text}`;
    })
    .catch(error => {
        console.error('Error:', error);
    });
}
  

  document.addEventListener('DOMContentLoaded', function() {
    const closeButton = document.querySelector('.close-button');
    closeButton.addEventListener('click', function() {
      const modal = document.getElementById('credential-modal');
      modal.style.display = 'none';
    });
  });
