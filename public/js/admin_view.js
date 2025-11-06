const SERVER_GET_ENV_URL = '/api/v1/admin/env';

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

const ADMIN_API_KEY = getCookie('admin_api_key');
if (!ADMIN_API_KEY) {
    window.location.href = '/';
}

const displayMessage = (text, isError = false) => {
    const msgElement = document.getElementById('message');
    msgElement.textContent = text;
    msgElement.className = isError ? 'error' : 'success';
    msgElement.style.display = 'block';
};

function getQueryParams() {
    const params = new URLSearchParams(window.location.search);
    return { project: params.get('project'), env: params.get('env') };
}

function syntaxHighlight(json) {
    if (typeof json != 'string') {
        json = JSON.stringify(json, undefined, 2);
    }
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false|null/.test(match)) {
            cls = 'boolean';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

async function loadEnvForView() {
    const { project, env } = getQueryParams();
    const viewResultElement = document.getElementById('viewResult');

    if (!project || !env) {
        document.getElementById('viewStatus').textContent = "Error: Project information is missing.";
        viewResultElement.textContent = "URL must include both project and env parameters.";
        return;
    }

    document.getElementById('viewStatus').textContent = `Fetching data for project "${project}/${env}"...`;

    try {
        const response = await fetch(SERVER_GET_ENV_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-API-Key': ADMIN_API_KEY
            },
            body: JSON.stringify({ project: project, env_name: env })
        });

        if (!response.ok) {
            throw new Error(`Data load failed (${response.status}): ${await response.text()}`);
        }

        const result = await response.json();
        const envData = result.envData;

        document.getElementById('viewStatus').textContent = `Project "${project}/${env}" loaded successfully:`;

        viewResultElement.innerHTML = syntaxHighlight(envData);

    } catch (e) {
        document.getElementById('viewStatus').textContent = `Load failed: ${e.message}`;
        viewResultElement.textContent = `Failed to load data. Error: ${e.message}`;
        console.error(e);
    }
}

document.addEventListener('DOMContentLoaded', loadEnvForView);