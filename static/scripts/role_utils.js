// Async unction to fetch and display roles
async function fetchRoles() {
    const roles = await fetch("/fetch?roles").then((res) => res.json());

    const roleDiv = document.querySelector(".roles");
    roleDiv.innerHTML = '';
    const roleCounter = document.getElementById('roleCounter');
    roleCounter.innerText = 'Roles (' + roles.length + ')';

    for (let role of roles) {
        const newRoleCard = document.createElement('div');
        newRoleCard.classList.add('card');
        newRoleCard.classList.add('d-flex');
        newRoleCard.classList.add('m-3');

        const newRoleCardBody = document.createElement('div');
        newRoleCardBody.classList.add('card-body');
        newRoleCardBody.classList.add('flex-row');
        newRoleCardBody.classList.add('d-flex');
        newRoleCardBody.classList.add('align-items-center');
                         
        const roleDetails = document.createElement('div');
        roleDetails.classList.add('flex-column');
        roleDetails.classList.add('flex-grow-1');
        roleDetails.classList.add('d-flex');
        roleDetails.classList.add('ms-3');

        const roleName = document.createElement('h1');
        roleName.classList.add('card-title');
        
        const roleBadge = document.createElement('span');
        roleBadge.classList.add('badge');
        switch (role.id) {
            case 0:
                roleBadge.classList.add('text-bg-success');
                roleBadge.innerText = "SYSTEM";
                newRoleCard.style.setProperty("border-style", "dashed");
                break;
            case 1:
                roleBadge.classList.add('text-bg-primary');
                roleBadge.innerText = "ADMIN";
                break;
            default:
                roleBadge.classList.add('text-bg-secondary');
                roleBadge.innerText = role.name.toUpperCase();
                break;
        }
        roleName.appendChild(roleBadge);

        const rolePerms = document.createElement('p');
        rolePerms.classList.add('card-text');

        for (perm of role.perms) {
            const rolePermsBadge = document.createElement('span');
            rolePermsBadge.classList.add('badge');
            rolePermsBadge.classList.add('m-1');
            
            switch (perm) {
                case "dashboard":
                case "profile":
                case "preferences":
                    rolePermsBadge.classList.add('text-bg-success');
                    rolePermsBadge.innerText = perm.toUpperCase();
                    break;
                case "register":
                case "edit":
                case "logs":
                case "fetch":
                case "add_role":
                    rolePermsBadge.classList.add('text-bg-warning');
                    rolePermsBadge.innerText = perm.toUpperCase();
                    break;
                case "delete":
                    rolePermsBadge.classList.add('text-bg-danger');
                    rolePermsBadge.innerText = perm.toUpperCase();
                    break;
                default:
                    rolePermsBadge.classList.add('text-bg-secondary');
                    rolePermsBadge.innerText = perm.toUpperCase();
                    break;
            }
            rolePerms.appendChild(rolePermsBadge);
        }

        roleDetails.appendChild(roleName);
        roleDetails.appendChild(rolePerms);

        const roleDeleteButton = document.createElement('button');
        roleDeleteButton.type = "button";
        roleDeleteButton.classList.add('btn');
        roleDeleteButton.classList.add('btn-danger');
        roleDeleteButton.classList.add('justify-content-md-end');
        roleDeleteButton.title = 'Delete Role';
        roleDeleteButton.onclick = () => {
            showDeleteModal(role.id);
        }
        roleDeleteButton.innerHTML = `<i class="bi bi-trash3"></i>`;

        newRoleCardBody.appendChild(roleDetails);

        if (role.id > 2) {
            newRoleCardBody.appendChild(roleDeleteButton);
        }
        
        newRoleCard.appendChild(newRoleCardBody);
        roleDiv.appendChild(newRoleCard);
    }

    const createNewRoleButton = document.createElement('button');
    createNewRoleButton.type = 'button';
    createNewRoleButton.classList.add('btn');
    createNewRoleButton.classList.add('btn-outline-primary');
    createNewRoleButton.classList.add('m-3');
    createNewRoleButton.classList.add('d-grid');
    createNewRoleButton.classList.add('gap-2');
    createNewRoleButton.classList.add('customButton');
    createNewRoleButton.classList.add('align-content-center');
    createNewRoleButton.innerHTML = `<h1><i class="bi bi-plus-lg"></i></h1>`;
    createNewRoleButton.title = "Register a new user";
    createNewRoleButton.setAttribute("data-bs-toggle", "modal");
    createNewRoleButton.setAttribute("data-bs-target", "#createRole");

    roleDiv.appendChild(createNewRoleButton);
}

// Async function to fetch permissions
async function fetchPerms() {
    const perms = await fetch("/fetch?perms").then((res) => res.json());
    const permSelect = document.querySelector("#perm-select");

    for (let perm of perms.perms) {
        const newOption = document.createElement("option");
        newOption.value = perm;
        newOption.innerText = perm;

        permSelect.appendChild(newOption);
    }
}

// Async function to create a role
async function createRole() {
    const roleForm = document.querySelector("#createRoleForm");
    const data = new URLSearchParams(new FormData(roleForm));
    const status = await fetch(
        "/add_role",
        {
            method: 'POST',
            body: data,
        }
    ).then((res) => res.json());

    return status;
}

// Async function to delete a role
async function deleteRole() {
    const formElement = document.getElementById("deleteForm");
    const data = new URLSearchParams(new FormData(formElement));
    const status = await fetch(
        "/delete?role="+data.get('id'),
        {
            method: 'POST',
            body: data,
        }).then((res)=>res.json());

    if (status.status) {
        appendAlert("Role " + data.get('id') + " has been successfully deleted.", "success");
    } else {
        appendAlert("Failed to delete role.", "error");
    }
}

// Function to show role delete modal manually (fix to that bug)
function showDeleteModal(id) {
    console.log("invoked")

    const deleteForm = document.getElementById("deleteForm");
    const role_id = document.createElement('input');
    role_id.type = 'hidden';
    role_id.value = id;
    role_id.name = "id";

    deleteForm.appendChild(role_id);

    bootstrap.Modal.getOrCreateInstance($('#deleteRoleConfirm').toArray()[0]).show();
}
