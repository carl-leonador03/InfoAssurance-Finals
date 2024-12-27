function checkVerify() {
    const newPassword = document.getElementById('newPassword');
    const verifyPassword = document.getElementById('verifyPassword');
    const invalidNewPassword = document.getElementById('invalidNewPassword');
    const invalidVerifyPassword = document.getElementById('invalidVerifyPassword');

    // check if the new password is a valid one
    if (newPassword.value != '') {
        const regex = RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[-+_!@#$%^&=*.,?]).+$');
        var isValid = regex.test(newPassword.value);
        if (!isValid) {
            invalidNewPassword.style.setProperty('display', 'block', 'important');
            newPassword.style.setProperty('border-color', 'var(--bs-form-invalid-border-color)', 'important');
        } else {
            invalidNewPassword.style.setProperty('display', 'none', 'important');
            newPassword.style.setProperty('border-color', 'var(--bs-border-color)', 'important');
        }
    } else {
        newPassword.style.setProperty('border-color', 'var(--bs-border-color)', 'important');
        invalidNewPassword.style.setProperty('border-color', 'var(--bs-border-color)', 'important');
    }  

    // now check if verify password isnt empty and assume that the user is inputting their own new password
    if (verifyPassword.value != '') {
        if (newPassword.value == verifyPassword.value) {
            newPassword.style.setProperty('border-color', 'var(--bs-form-valid-border-color)', 'important');
            verifyPassword.style.setProperty('border-color', 'var(--bs-form-valid-color)', 'important');                            
            invalidVerifyPassword.style.setProperty('display', 'none', 'important');
        } else {
            newPassword.style.setProperty('border-color', 'var(--bs-form-invalid-border-color)', 'important');
            verifyPassword.style.setProperty('border-color', 'var(--bs-form-invalid-color)', 'important');                            
            invalidVerifyPassword.style.setProperty('display', 'block', 'important');
        }
    } else {
        verifyPassword.style.setProperty('border-color', 'var(--bs-border-color)', 'important');
    }
}

function password_toggle(endpoint) {
    const show_eye = document.getElementById("show_eye");
    const hide_eye = document.getElementById("hide_eye");

    hide_eye.classList.remove("d-none");

    if (endpoint == 'login') {
        const password_form = document.getElementById("password");

        if (password_form.type == "password") {
            password_form.type = "text";
            show_eye.classList.add("d-none");
            hide_eye.classList.remove("d-none");
        } else {
            password_form.type = "password";
            show_eye.classList.remove("d-none");
            hide_eye.classList.add("d-none");
        }

    } else {
        const newPassword = document.getElementById("newPassword");
        const verifyPassword = document.getElementById("verifyPassword");

        if (newPassword.type == "password") {
            newPassword.type = "text";
            verifyPassword.type = "text";
            show_eye.classList.add("d-none");
            hide_eye.classList.remove("d-none");
        } else {
            newPassword.type = "password";
            verifyPassword.type = "password";
            show_eye.classList.remove("d-none");
            hide_eye.classList.add("d-none");
        }

    }
}