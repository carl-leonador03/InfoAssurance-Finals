function setTheme(theme) {
    if (!document.documentElement.getAttribute('data-bs-theme')) {
        document.documentElement.setAttribute('data-bs-theme', theme);
        document.documentElement.classList = '';
        document.documentElement.classList.add(theme + '-bg-img');
    } else if (document.documentElement.getAttribute('data-bs-theme') != theme) {
        document.documentElement.setAttribute('data-bs-theme', theme);
        document.documentElement.classList = '';
        document.documentElement.classList.add(theme + '-bg-img');
    }

    if (theme == "dark") {
        document.querySelector('#btnSwitch').classList.replace('btn-dark', 'btn-light');
        document.querySelector('#btnSwitch').innerHTML = `<i class="bi bi-sun-fill"></i>`;
    } else {
        document.querySelector('#btnSwitch').classList.replace('btn-light', 'btn-dark');
        document.querySelector('#btnSwitch').innerHTML = `<i class="bi bi-moon-fill"></i>`;
    }
}


document.getElementById('btnSwitch').addEventListener('click',()=>{
    if (document.documentElement.getAttribute('data-bs-theme') == 'dark') {
        setTheme('light');
    }
    else {
        setTheme('dark');
    }
});