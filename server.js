// server.js — Lance le bot Discord et l'API en même temps
require('./api');    // démarre Express sur le port API_PORT
require('./index');  // démarre le bot Discord
