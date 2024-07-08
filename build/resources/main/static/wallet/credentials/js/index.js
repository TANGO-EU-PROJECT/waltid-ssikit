document.addEventListener('DOMContentLoaded', function() {
    fetchCredentials();
  });
  
  function fetchCredentials() {
    fetch('https://umu-webWallet:30002/listCredentials')
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
    
    // Check if the delete button already exists
    let deleteButton = modal.querySelector('#delete-button');
    if (!deleteButton) {
      // Create the delete button if it doesn't exist
      deleteButton = document.createElement('button');
      deleteButton.id = 'delete-button';
      deleteButton.textContent = 'Delete';
      
      // Add click event listener to the button
      deleteButton.onclick = function() {
        deleteCredential(credential.name);
      };
      
      // Append the button to the modal
      modalcontent.appendChild(deleteButton);
    }
    
    // Display the modal
    modal.style.display = 'block';
  }
  
  function deleteCredential(name) {

    const formData = new FormData();
    formData.append('nameCred', name);

    fetch('https://umu-webWallet:30002/deleteCredential', {
    method: 'POST',
    body: formData
    })
    .then(response => response.text()) 
    .then(text => {
    console.log(text); 
    window.location.href = "/credentials"; 
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
