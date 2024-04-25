document.addEventListener('DOMContentLoaded', function() {
    fetchCredentials();
  });
  
  function fetchCredentials() {
    fetch('https://umu-webWallet:8445/validCredentials')
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
      window.location.href = `https://umu-webWallet:8445/login`
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

    fetch('https://umu-webWallet:8445/selectCredential', {
        method: 'POST',
        headers: {
            'Content-Type': 'text/plain', 
        },
        body: credential 
    })
    .then(response => response.text()) 
    .then(text => {
        console.log(text); 
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
  