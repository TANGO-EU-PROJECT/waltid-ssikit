document.getElementById('verifyButton').addEventListener('click', function() {
    fetch('https://umu-verifier:<VERIFIER_PORT>/vpToken')
        .then(response => response.text()) 
        .then(vpToken => {
            const finalUrl = `https://umu-webWallet:<WALLET_PORT>/demo?vpToken=${encodeURIComponent(vpToken)}`;
            console.log(finalUrl)
            window.location.href = finalUrl;
        })
        .catch(error => console.error('Error al obtener el vpToken:', error));
});
