#!/usr/bin/env node

import { program } from 'commander';
import fetch  from 'node-fetch';
import fs  from 'fs';

program
  .name('sharenv')
  .description('Fetch environment variables from sharenv server and create .env file')
  .version('1.0.0');

program
  .command('pull')
  .description('Download env variables and generate .env file')
  .requiredOption('-p, --project <project>', 'Project name')
  .requiredOption('-e, --env <env>', 'Environment name (dev/stage/prod)')
  .requiredOption('-u, --url <url>', 'Sharenv server base URL, e.g. http://localhost:3000')
  .option('-t, --token <token>', 'Authentication token')
  .action(async (opts) => {
    const { project, url, env, token } = opts;

    const headers = {
        'Content-Type': 'application/json',
        ...(token && { 'x-forwarded-for': token })
    };

    try {
      const res = await fetch(`${url}/api/v1/env/${project}/${env}`,{
          method: 'GET',
          headers: headers
      });
      if (!res.ok) {
        console.error(`Failed to fetch env: ${res.status} ${res.statusText}`);
        process.exit(1);
      }
      const envJson = await res.json();

      let envText = '';
      for (const [key, value] of Object.entries(envJson)) {
        envText += `${key}=${value}\n`;
      }

      fs.writeFileSync('.env.example', envText);
      console.log(`.env file created successfully for project '${project}'.`);
    } catch (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

program.parse(process.argv);
