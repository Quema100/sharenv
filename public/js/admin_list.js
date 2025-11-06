const SERVER_PROJECTS_URL = '/api/v1/admin/projects';
const SERVER_DELETE_URL = '/api/v1/admin/delete';

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

const ADMIN_API_KEY = getCookie('admin_api_key');
if (!ADMIN_API_KEY) { window.location.href = '/'; }

const displayMessage = (text, isError = false) => {
    const msgElement = document.getElementById('globalMessage');
    if (!msgElement) return;
    msgElement.textContent = text;
    msgElement.className = isError ? 'error' : 'success';
    msgElement.style.display = 'block';
};


let groupedProjects = {};
let allEnvironments = [];

let currentState = JSON.parse(localStorage.getItem('adminListViewState')) || { type: 'initial', project: null };


function saveState(type, project = null) {
    currentState = { type, project };
    localStorage.setItem('adminListViewState', JSON.stringify(currentState));
}
async function loadProjectList() {
    const listElement = document.getElementById('projectList');
    const statusElement = document.getElementById('projectListStatus');
    listElement.innerHTML = '';
    statusElement.textContent = 'Loading list...';

    try {
        const response = await fetch(SERVER_PROJECTS_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Admin-API-Key': ADMIN_API_KEY },
            body: JSON.stringify({ action: 'list' })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API access fail (${response.status}): ${errorText.substring(0, 50)}...`);
        }

        allEnvironments = await response.json();

        if (allEnvironments.length === 0) {
            statusElement.textContent = 'No registered projects found.';
            displayMessage('No saved projects available at the moment.', true);
            return;
        }

        groupedProjects = {};
        allEnvironments.forEach(p => {
            if (!groupedProjects[p.project]) {
                groupedProjects[p.project] = [];
            }
            groupedProjects[p.project].push(p);
        });

        statusElement.textContent = `There are a total of ${Object.keys(groupedProjects).length} projects.`;

        Object.keys(groupedProjects).forEach(projectName => {
            const item = document.createElement('div');
            item.className = 'project-list-item';
            item.id = `project-${projectName}`;
            item.innerHTML = `
                <div class="project-details">
                    <strong>${projectName}</strong>
                    <br><span>(${groupedProjects[projectName].length} environments)</span>
                </div>
            `;
            item.onclick = () => showProjectDetails(projectName);
            listElement.appendChild(item);
        });

        if (currentState.type === 'project' && currentState.project && groupedProjects[currentState.project]) {
            showProjectDetails(currentState.project);
        } else if (currentState.type === 'all') {
            showAllEnvironments();
        } else {
            document.getElementById('initialContent').style.display = 'block';
            document.getElementById('projectDetailView').style.display = 'none';
            document.querySelectorAll('.project-list-item').forEach(el => el.classList.remove('active'));
        }

    } catch (e) {
        statusElement.textContent = `Failed to load list`;
        displayMessage(`Error: ${e.message}`, true);
        console.error(e);
    }
}

function showProjectDetails(projectName) {
    saveState('project', projectName);
    document.getElementById('initialContent').style.display = 'none';
    document.getElementById('projectDetailView').style.display = 'block';
    document.querySelectorAll('.project-list-item').forEach(el => el.classList.remove('active'));
    document.getElementById(`project-${projectName}`).classList.add('active');

    document.getElementById('envListTitle').textContent = `Environment variables for ${projectName}`;

    const envListElement = document.getElementById('envList');
    envListElement.innerHTML = '';

    const envs = groupedProjects[projectName];

    if (!envs || envs.length === 0) {
        envListElement.innerHTML = '<p>No environments registered for this project.</p>';
        document.getElementById('envMetadata').textContent = '0 environments';
        return;
    }

    document.getElementById('envMetadata').textContent = `${envs.length} environments (Data Files)`;

    envs.forEach(env => {
        const item = document.createElement('div');
        item.className = 'env-item';
        item.innerHTML = `
            <div>
                <strong>${env.env}</strong>
                <small>${env.project}/${env.env}</small>
            </div>
            <div>
                <button class="action-button action-button-view" onclick="redirectToView('${env.project}', '${env.env}')">View</button>
                <button class="action-button action-button-edit" onclick="redirectToEdit('${env.project}', '${env.env}')">Edit</button>
                <button class="action-button action-button-delete" style="background-color: #dc3545;" onclick="confirmDelete('${env.project}', '${env.env}')">Delete</button>
            </div>
        `;
        envListElement.appendChild(item);
    });
}

function showAllEnvironments() {
    saveState('all', null);
    document.getElementById('initialContent').style.display = 'none';
    document.getElementById('projectDetailView').style.display = 'block';
    document.querySelectorAll('.project-list-item').forEach(el => el.classList.remove('active'));

    document.getElementById('envListTitle').textContent = `All Environment Variables`;
    document.getElementById('envMetadata').textContent = `${allEnvironments.length} environments`;

    const envListElement = document.getElementById('envList');
    envListElement.innerHTML = '';

    if (allEnvironments.length === 0) {
        envListElement.innerHTML = '<p>No environments registered.</p>';
        return;
    }

    allEnvironments.forEach(env => {
        const item = document.createElement('div');
        item.className = 'env-item';
        item.innerHTML = `
            <div>
                <strong style="color: #81a4ff;">${env.project}</strong> / <strong>${env.env}</strong>
                <small>${env.project}/${env.env}</small>
            </div>
            <div>
                <button class="action-button action-button-view" onclick="redirectToView('${env.project}', '${env.env}')">View</button>
                <button class="action-button action-button-edit" onclick="redirectToEdit('${env.project}', '${env.env}')">Edit</button>
                <button class="action-button action-button-delete" style="background-color: #dc3545;" 
                        onclick="confirmDelete('${env.project}', '${env.env}')">Delete</button>
            </div>
         `;
        envListElement.appendChild(item);
    });
}


function confirmDelete(project, env) {

    const confirmation = prompt(`Are you sure you want to delete the '${project}/${env}' environment?\nThis action cannot be undone.\n\nType "DELETE" to confirm:`);

    if (confirmation !== 'DELETE') {
        displayMessage('Deletion cancelled.', false);
        return;
    }

    deleteEnv(project, env);
}

async function deleteEnv(project, env) {
    displayMessage('Deleting...', false);
    try {
        const response = await fetch(SERVER_DELETE_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Admin-API-Key': ADMIN_API_KEY },
            body: JSON.stringify({
                project: project,
                env_name: env,
            })
        });

        if (!response.ok) {
            throw new Error(`Delete fail (${response.status}): ${await response.text()}`);
        }

        displayMessage(`'${project}/${env}' environment has been successfully deleted.`, false);

        loadProjectList();
        document.getElementById('projectDetailView').style.display = 'none';
        document.getElementById('initialContent').style.display = 'block';

    } catch (e) {
        displayMessage(`Delete error: ${e.message}`, true);
        console.error(e);
    }
}

async function handleLogout() {
    try {
        const response = await fetch('/admin/logout', { method: 'POST' });

        if (response.ok) {
            window.location.href = '/';
        } else {
            console.error('Logout failed on server, forcing client redirects.');
            window.location.href = '/';
        }
    } catch (e) {
        console.error('Logout error:', e);
        window.location.href = '/';
    }
}

function redirectToView(project, env) {
    window.location.href = `/admin/view?project=${project}&env=${env}`;
}

function redirectToEdit(project, env) {
    window.location.href = `/admin/edit?project=${project}&env=${env}`;
}

document.addEventListener('DOMContentLoaded', loadProjectList);