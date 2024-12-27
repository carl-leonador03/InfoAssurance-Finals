const alertPopup = document.getElementById('alertPopup');

// Creates a new alert
function appendAlert(message, type) {
    type = type == 'error' ? 'danger' : type;
    const wrapper = document.createElement('div');
    const icons = {
        'danger': `<i class="bi bi-x-circle"></i>`,
        'warning': `<i class="bi bi-exclamation-triangle"></i>`,
        'info': `<i class="bi bi-info-circle-fill"></i>`,
        'success': `<i class="bi bi-check-circle"></i>`
    }

    wrapper.innerHTML = [
        `<div class="alert alert-${type} d-flex align-items-center alert-dismissible" role="alert">`,
        `   <div>${icons[type]} ${message}</div>`,
        `   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`,
        `</div>`
    ].join('')

    // check if there are any old undismissed popups
    if (alertPopup.children.length != 0) {
        alertPopup.innerHTML = '';
    }
    
    alertPopup.parentElement.style.removeProperty('margin-bottom');
    alertPopup.append(wrapper);
}

// Little hack to load alerts from flash() function from Flask
function loadMessages (flashed_messages_str) {
    var flash_messages;

    // Manually parse the string into an array.
    try {
        flash_messages = JSON.parse(flashed_messages_str.replaceAll('&#39;', '"').replace(/\(/g, "[").replace(/\)/g, "]").replaceAll('&#34;', "'"));
    } catch (SyntaxError) {
        flash_messages = JSON.parse(flashed_messages_str.replace('&#39;', '"').replace('&#39;', '"').replace(/\(/g, "[").replace(/\)/g, "]").replaceAll('&#39;', "'").replaceAll('&#34;', '"'))
    }
    

    for (let flash_message of flash_messages) {
        appendAlert(flash_message[1], flash_message[0]);
    }
}