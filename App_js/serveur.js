const fs = require("fs");
const https = require("https");
const express = require("express");
const path = require("path");
const cbor = require("cbor"); // ← ici

const app = express();
const PORT = 8443;

// Remplace les chemins par ceux où mkcert a généré les fichiers
const options = {
  key: fs.readFileSync("localhost-key.pem"),
  cert: fs.readFileSync("localhost.pem"),
};

app.use(express.static(path.join(__dirname)));

app.listen(3000, () => {
  console.log("HTTP serveur sur http://localhost:3000");
});

https.createServer(options, app).listen(PORT, () => {
  console.log(`HTTPS serveur lancé sur https://localhost:${PORT}`);
});
