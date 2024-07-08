document.addEventListener('DOMContentLoaded', function() {
    const params = new URLSearchParams(window.location.search);
    const errorMessage = params.get('error');
    document.getElementById('errorMessage').textContent = errorMessage || 'Unknown error';
});
