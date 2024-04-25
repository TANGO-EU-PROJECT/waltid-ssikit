document.getElementById('verifyButton').addEventListener('click', function() {
    fetch('https://umu-verifier:8444/vpToken')
        .then(response => response.text()) 
        .then(vpToken => {
            const finalUrl = `https://umu-webWallet:8445/demo?vpToken=${encodeURIComponent(vpToken)}`;
            console.log(finalUrl)
            window.location.href = finalUrl;
        })
        .catch(error => console.error('Error al obtener el vpToken:', error));
});
