// This file contains no secrets — used as a clean fixture
const API_ENDPOINT = process.env.API_ENDPOINT || 'https://api.example.com';
export const getUser = async (id) => fetch(`${API_ENDPOINT}/users/${id}`);
