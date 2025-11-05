import fetch from 'node-fetch';

async function getData() {
  const url = 'http://localhost:3000/api/v1/env/my-app/development'; 

  try {
    const response = await fetch(url, {
      method: 'GET', 
      headers: {
        'Content-Type': 'application/json', 
        'x-forwarded-for': '127.0.0.1'
      },
    });

    if (!response.ok) { 
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json(); 
    console.log('Data received:', data);

  } catch (error) {
    console.error('Request failed:', error);
  }
}

getData();