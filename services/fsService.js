const fs = require('fs-extra');
const path = require('path');

const DATA_DIR = path.join(__dirname, '../data');

const getFilePath = (project, env) => {
    return path.join(DATA_DIR, `${project}`, `${project}_${env}.json`);
};

exports.exists = async (project, env) => {
    const filePath = getFilePath(project, env);
    return await fs.pathExists(filePath);
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

/**
 * Deletes an encrypted data file.
 * If the parent project directory becomes empty after deletion,
 * it removes the project directory as well.
 * @param {string} project - Project name
 * @param {string} env - Environment (dev/prod, etc.)
 */
exports.deleteEncryptedData = async (project, env) => {
    const filePath = getFilePath(project, env);
    const projectDir = path.join(DATA_DIR, project);

    if (!await fs.pathExists(filePath)) {
        throw new Error('FILE_NOT_FOUND');
    }

    await fs.remove(filePath);

    try {
        const files = await fs.readdir(projectDir);
        if (files.length === 0) {
            await fs.rmdir(projectDir);
            console.log(`Removed empty directory: ${projectDir}`);
        }
    } catch (e) {
        console.error(`Error cleaning up directory ${projectDir}: ${e.message}`);
    }
};