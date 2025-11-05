const fs = require('fs-extra');
const path = require('path');

const DATA_DIR = path.join(__dirname, '../data');

const getFilePath = (project, env) => {
    return path.join(DATA_DIR, `${project}`, `${project}_${env}.json`);
};

/**
 * Saves the final encrypted data to a file.
 * @param {string} project - Project name
 * @param {string} env - Environment (dev/prod, etc.)
 * @param {object} data - Encrypted JSON data object
 */
exports.saveEncryptedData = async (project, env, data) => {
    const projectDir = path.join(DATA_DIR, project);
    const filePath = getFilePath(project, env);

    await fs.ensureDir(projectDir);
    await fs.outputJson(filePath, data, { spaces: 2 });
};

/**
 * Reads encrypted data from a file.
 * @param {string} project - Project name
 * @param {string} env - Environment (dev/prod, etc.)
 * @returns {object} File content (JSON object)
 */
exports.getEncryptedData = async (project, env) => {
    const filePath = getFilePath(project, env);
    if (!await fs.pathExists(filePath)) {
        throw new Error('FILE_NOT_FOUND');
    } return fs.readJson(filePath);
};