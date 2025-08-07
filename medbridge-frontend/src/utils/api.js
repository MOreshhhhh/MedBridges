// src/utils/api.js
import axios from 'axios';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api', // adjust base URL if needed
});

// Attach your auth token from localStorage or other storage to each request
api.interceptors.request.use(config => {
  const token = localStorage.getItem('token'); // or wherever your JWT is stored
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;
