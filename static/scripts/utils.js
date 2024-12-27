// Function to set the site's theme (dark or light for now)
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

// Helper function to limit values to alphabet characters (for role name input)
function limitInput(e) {
    let t = e.target;
    let badValues = /[^a-zA-Z]+/g;
    t.value = t.value.replace(badValues, '');
}

document.getElementsByName("rolename")[0].addEventListener('input', limitInput);