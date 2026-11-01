// Example API that uses express and axios (not lodash.merge)
const express = require('express');
const axios = require('axios');

const app = express();

app.get('/api/data', async (req, res) => {
  const response = await axios.get('https://api.example.com/data');
  res.json(response.data);
});

app.listen(3000);
