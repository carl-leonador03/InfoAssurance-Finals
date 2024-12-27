async function fetchUsers() {
    const users = await fetch("/fetch?users").then((res) => res.json());

    const userDiv = document.querySelector(".users");
    userDiv.innerHTML = '';
    const userCounter = document.getElementById('userCounter');
    userCounter.innerText = 'Users (' + users.length + ')';

    for (let user of users) {
        const newUserCard = document.createElement('div');
        newUserCard.classList.add('card');
        newUserCard.classList.add('d-flex');
        newUserCard.classList.add('m-3');

        const newUserCardBody = document.createElement('div');
        newUserCardBody.classList.add('card-body');
        newUserCardBody.classList.add('flex-row');
        newUserCardBody.classList.add('d-flex');
        newUserCardBody.classList.add('align-items-center');
        
        const userPfp = document.createElement('img');
        userPfp.style.width = '48px';
        userPfp.style.height = '48px';
        userPfp.style.setProperty('border-radius', '50%');
        userPfp.style.setProperty('object-fit', 'cover');
        userPfp.src = user['pfp']['image_path'];
        newUserCardBody.appendChild(userPfp);
                         
        const userDetails = document.createElement('div');
        userDetails.classList.add('flex-column');
        userDetails.classList.add('flex-grow-1');
        userDetails.classList.add('d-flex');
        userDetails.classList.add('ms-3');

        const userName = document.createElement('h5');
        userName.classList.add('card-title');
        userName.innerText = user.name + " ";

        const userRoleBadge = document.createElement('span');
        userRoleBadge.classList.add('badge');
        switch (user.role.id) {
            case 1:
                userRoleBadge.classList.add('text-bg-primary');
                userRoleBadge.innerText = "ADMIN";
                break;
            case 2:
                userRoleBadge.classList.add('text-bg-secondary');
                userRoleBadge.innerText = "USER";
                break;
        }
        userName.appendChild(userRoleBadge);

        const userUsername = document.createElement('p');
        userUsername.classList.add('card-text');
        userUsername.innerText = "[" + user.id  + "] " + user.username;

        userDetails.appendChild(userName);
        userDetails.appendChild(userUsername);

        const userProfileButton = document.createElement('button');
        userProfileButton.type = "button";
        userProfileButton.classList.add('btn');
        userProfileButton.classList.add('btn-success');
        userProfileButton.classList.add('mx-3');
        userProfileButton.classList.add('justify-content-md-end');
        userProfileButton.title = 'View User Profile';
        userProfileButton.onclick = function() {
            const url = window.location.origin;
            window.location.href = url + "/profile/" + user.id;
        }
        userProfileButton.innerHTML = `<i class="bi bi-person-circle"></i>`;

        const userEditButton = document.createElement('button');
        userEditButton.type = "button";
        userEditButton.classList.add('btn');
        userEditButton.classList.add('btn-warning');
        userEditButton.classList.add('justify-content-md-end');
        userEditButton.title = 'Edit User Details';
        userEditButton.onclick = function() {
            const url = window.location.origin;
            window.location.href = url + "/edit/" + user.id;
        }
        userEditButton.innerHTML = `<i class="bi bi-pencil-square"></i>`;

        newUserCardBody.appendChild(userDetails);
        newUserCardBody.appendChild(userProfileButton);
        newUserCardBody.appendChild(userEditButton);
        newUserCard.appendChild(newUserCardBody);
        userDiv.appendChild(newUserCard);
    }

    const createNewUserButton = document.createElement('button');
    createNewUserButton.classList.add('btn');
    createNewUserButton.classList.add('btn-outline-primary');
    createNewUserButton.classList.add('m-3');
    createNewUserButton.classList.add('d-grid');
    createNewUserButton.classList.add('gap-2');
    createNewUserButton.classList.add('customButton');
    createNewUserButton.classList.add('align-content-center');
    createNewUserButton.innerHTML = `<h1><i class="bi bi-plus-lg"></i></h1>`;
    createNewUserButton.title = "Register a new user";
    createNewUserButton.onclick = () => window.location.pathname = "/register";
    

    userDiv.appendChild(createNewUserButton);
}

async function deleteUser() {
    console.log("deleteUser invoked.");
    const formElement = document.getElementById("deleteForm");
    const data = new URLSearchParams(new FormData(formElement));
    const status = await fetch(
        "/delete?user="+data.get('user_id'),
        {
            method: 'POST',
            body: data,
        }).then((res)=>res.json());

    if (status.status) {
        const confirmationCard = document.createElement('div');
        confirmationCard.classList.add("card");
        confirmationCard.classList.add("border-success");
        confirmationCard.classList.add("d-block");
        confirmationCard.classList.add("m-5");
        confirmationCard.classList.add("w-auto");
        confirmationCard.classList.add("h-auto");

        const confirmationCardBody = document.createElement('div');
        confirmationCardBody.classList.add('card-body');
        confirmationCardBody.classList.add('text-success');

        const confirmationCardTitle = document.createElement('h5');
        confirmationCardTitle.classList.add("card-title");
        confirmationCardTitle.innerHTML = `<i class="bi bi-check-circle"></i>` + " Account deleted";

        const confirmationCardText = document.createElement('p');
        confirmationCardText.classList.add("card-text");
        confirmationCardText.innerText = `Account '${data.get('user_id')}' has been successfully deleted. You will be redirected back to the dashboard.`;

        confirmationCardBody.appendChild(confirmationCardTitle);
        confirmationCardBody.appendChild(confirmationCardText);
        confirmationCard.appendChild(confirmationCardBody);
        document.getElementById('deleteCard').remove();
        document.getElementById('editForm').innerHTML = '';
        document.getElementById('editForm').appendChild(confirmationCard);
        
        await delay(3000);
        window.location.pathname = "/";
    }
}