# SecurEnv

SecurEnv is a lightweight, self-hosted web service designed for secure file uploading and sharing without the need for an external database.

## Table of Contents

* [Features](#features)
* [Security Model](#security-model)
    * [Admin Authentication (Password + RSA)](#admin-authentication-password--rsa)
    * [Client Authentication (IP Whitelist)](#client-authentication-ip-whitelist)
    * [Data Encryption (AES + RSA Hybrid)](#data-encryption-aes--rsa-hybrid)
* [Technology Stack](#technology-stack)
* [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Installation](#installation)
    * [Run](#run)
* [Usage](#usage)
    * [1. Admin Panel (Web UI)](#1-admin-panel-web-ui)
        * [Logging In](#logging-in)
        * [Managing Projects (List/View)](#managing-projects-listview)
        * [Registering a New ENV](#registering-a-new-env)
        * [Editing & Deleting](#editing--deleting)
    * [2. Client CLI (sharenv)](#2-client-cli-sharenv)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)

## Features

* Zero Database Required: Operates without any external database, storing encrypted environment files directly on the server's file system.

* Strong Admin Authentication: Secures the admin panel using a two-factor approach: a **PBKDF2-hashed** password and an RSA public key challenge.

* Client-Side Security: Utilizes an IP-based whitelist to ensure that only authorized applications and servers can fetch environment variables.

* Hybrid Encryption: Data is not stored in plaintext. It is encrypted using **AES-256** (symmetric) and the AES key itself is encapsulated with RSA (asymmetric) for maximum security.

* Automatic Setup: A guided command-line setup runs on first launch to automatically generate RSA keys, set the admin password, and configure the server.

* Full Admin UI: A complete web interface for administrators to list, register, edit, and view all environment variables.

* Client CLI Tool: Includes a simple `sharenv` CLI tool for fetching and generating `.env` files in deployment or CI/CD pipelines.


## Security Model

SecurEnv is built on a two-part security model: one for the administrator managing the secrets, and one for the clients consuming them.

### Admin Authentication (Password + RSA)

Access to the admin panel is protected by a strict, two-factor authentication process:  
1. Password (Knowledge): The admin must provide a password, which is verified against a ***PBKDF2-hashed** secret on the server.   
2. RSA Key Proof (Possession): The admin must provide the server's **Public Key**. The server sends a random `challenge` string, which the client encrypts with this **public key**. The server then decrypts it with its **Private Key**. This proves the admin has access to the correct **public key**, preventing unauthorized access.  

Once logged in, the server issues two cookies:  
* `secur_admin_session`: An HttpOnly cookie to maintain the session.
* `admin_api_key`: A JavaScript-accessible cookie used as an anti-CSRF token in API request headers.

### Client Authentication (IP Whitelist)

The client API (`GET /api/v1/env/...`) is open but secure. It does not require a key but strictly enforces an IP whitelist.

1. A client sends a GET request.
2. The SecurEnv server identifies the client's IP address (using `x-forwarded-for` or `req.socket.remoteAddress`).
3. The server decrypts the requested file.
4. It checks if the client's IP is present in the `WHITELIST_IPS` array inside the decrypted file.

> [!NOTE]   
> If the IP address matches, the environment variables are returned with a 200 OK response.  
> If the IP address does not match, access is denied with a 403 Forbidden response.  

### Data Encryption (AES + RSA Hybrid)

Data is never stored in plaintext.  
1. When an admin saves an ENV file, the JSON data is encrypted with a new, random AES-256 key.  
2. This AES key is then encrypted using the server's RSA Public Key.
3. The final file stores the AES-encrypted data and the RSA-encrypted AES key separately.

To read the file, the server uses its RSA Private Key to decrypt the AES key, then uses that AES key to decrypt the data.
## Technology Stack

* Backend: Node.js, Express.js
* Frontend: HTML, CSS, JavaScript
* Security: Node.js crypto module (PBKDF2, RSA, AES)
* Storage: Encrypted JSON files on the local file system (fs-extra)
* Client CLI: Node.js, commander, node-fetch

## Getting Started
### Prerequisites

* Node.js 22.16+
* `npm (or pnpm/yarn)` (Node Package Manager)

### Installation

1.  **Clone the repository:** (If this is from a GitHub repo)  
    ```bash
    git clone https://github.com/Quema100/sharenv.git
    cd sharenv
    ```
    (If you received the files directly, just navigate to the project directory.)

2.  **Install dependencies:**
    ```bash
    npm install express morgan dotenv fs-extra 
    ```

> [!NOTE]
> If you are using the CLI, please add the following libraries. 
> ```bash
> npm install commander node-fetch
> ```

### Run
The first time you run the server, it will guide you through the setup:  
```bash
npm start
```  
You will be prompted to:  
1. Generate RSA Keys: This creates `public_key.pem` and sets the `RSA_PRIVATE_KEY` in `.env`.
2. Set Port: Specify the port for the server.
3. Set Admin Password: Enter a secure password (min. 8 characters). This will be hashed and stored in `.env`.  

After setup, the server will start.  

## Usage
### 1. Admin Panel (Web UI)

Logging In
1. Go to http://localhost:3000 (or your configured URL).
2. Enter the Admin Password you created during setup.
3. Open the `public_key.pem` file, copy its entire contents (including `-----BEGIN...-----`), and paste it into the `RSA Public Key` text area.
4. Click "Authenticate & Connect".

#### Logging In
#### Managing Projects (List/View)

* Project List (Sidebar): After logging in, you are redirected to `/admin/list`. The sidebar shows a list of all projects.
* View Environments (Main Area): Clicking a project in the sidebar displays all environments for that project in the main area.
* View All: Click "View All Environments" to see every ENV file at once.
* View (Read-Only): Click "View" on any environment to go to `/admin/view` and see a read-only, formatted JSON view of the decrypted data.

#### Registering a New ENV

1. Click the "Register New Project" button.
2. Fill in the RSA Public Key.
3. Enter the Project Name and Environment.
4. Enter the Environment Variables as a valid JSON object.
5. Enter the Whitelist IP/Token ID List (comma-separated). This is crucial for client access.
6. Click "Encrypt and Save to Server".

#### Editing & Deleting

* Edit: From the list, click "Edit" on an environment. This takes you to `/admin/edit`. The server loads and decrypts the data. You can edit the JSON directly and resave it.
* Delete: From the list, click "Delete". You will be asked to confirm by typing "DELETE". This action is irreversible.

### 2. Client CLI (sharenv)
The clientCli.mjs script is used by your applications to fetch variables.

Link the CLI:
```bash
npm link
```

Usage:  
```bash
sharenv pull -u http://localhost:3000 -p my-app -e development -o path\to\.env
```

## Contributing
Feel free to fork this repository, open issues, and submit pull requests. Suggestions for improving realism, or code quality are welcome.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
For questions or discussions related to this simulation, please open an issue in the GitHub repository.