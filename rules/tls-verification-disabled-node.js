const https = require("https");
const tls = require("tls");

// ruleid: node-tls-verification-disabled
const agent = new https.Agent({ rejectUnauthorized: false });

// ruleid: node-tls-verification-disabled
const socket = tls.connect({ host: "example.com", port: 443, rejectUnauthorized: false });

const options = {};
// ruleid: node-tls-verification-disabled
options.rejectUnauthorized = false;

// ruleid: node-tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ok: node-tls-verification-disabled
const safeAgent = new https.Agent({ rejectUnauthorized: true, ca: privateCa });

// ok: node-tls-verification-disabled
const defaultAgent = new https.Agent({ keepAlive: true });

// ok: node-tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
