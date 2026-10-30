
import express from "express";
import https from "node:https";
import "dotenv/config";
import {
  importPKCS8,
  importSPKI,
  compactDecrypt,
  jwtVerify,
} from "jose";

import { readFile } from "node:fs/promises";

const app = express();
const PORT = process.env.PORT || 3000;

const tlsOptions = {
  key: await readFile("./mtls-outbound/server-key.pem"),
  cert: await readFile("./mtls-outbound/server-cert.pem"),

  // Trust this specific self-signed client certificate.
 ca: await readFile("./mtls-outbound/client-cert.pem"),

  // Require and validate the client's certificate.
  requestCert: true,
  rejectUnauthorized: true,

  minVersion: "TLSv1.2",
};


// Parse application/x-www-form-urlencoded request bodies.
app.use(express.urlencoded({ extended: false }));

// Load cryptographic keys once at startup.
// The API owns the JWE decryption private key and the
// trusted sender's JWS verification public key.
const decryptionKey = await importPKCS8(
  await readFile("./keys/jwe-private.pem", "utf8"),
  "RSA-OAEP-256"
);

const verificationKey = await importSPKI(
  await readFile("./keys/jws-public-key.pem", "utf8"),
  "RS256"
);

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters.charAt(randomIndex);
    }
    
    return result;
}

// Authentication middleware: decrypt JWE, then verify JWS/JWT.
async function authenticate(req, res, next) {
  try {
     console.log("*************************************************************************************");
    console.log(req.headers);
    const authorization = req.headers.authorization;

    

    if (!authorization?.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Missing bearer token",
      });
    }

    const token = authorization.slice("Bearer ".length);

    // Step 1: Decrypt the outer JWE.
    const { plaintext, protectedHeader } = await compactDecrypt(
      token,
      decryptionKey,
      {
        keyManagementAlgorithms: ["RSA-OAEP-256"],
        contentEncryptionAlgorithms: ["A256CBC-HS512"],
      }
    );

    // Expect the encrypted content to be a signed JWT.
    if (protectedHeader.cty !== "JWT") {
      return res.status(401).json({
        error: "Unexpected encrypted token content",
      });
    }

    const innerToken = new TextDecoder().decode(plaintext);

    // Step 2: Verify the inner JWS/JWT signature and claims.
    const { payload } = await jwtVerify(
      innerToken,
      verificationKey,
      {
        algorithms: ["RS256"],
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
      }
    );

    // jwtVerify also checks exp and nbf when present.
    // Require exp so that tokens cannot be valid indefinitely.
    if (typeof payload.exp !== "number") {
      return res.status(401).json({
        error: "Token expiration is required",
      });
    }

    req.auth = payload;
     console.log("***********JWT TOKEN******************");
    console.log(payload);
    console.log("*************************************************************************************");

    next();
  } catch (error) {
    // Log details internally if needed; don't expose crypto errors.
    console.error("Authentication failed:", error.message);

    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

// Protected POST endpoint.
app.post("/api/submit", authenticate, (req, res) => {
  console.log("***********BODY******************");
   console.log(req.body);
  console.log("***********BODY******************");

  const { client, market, id } = req.body;

  if (
    typeof client !== "string" ||
    typeof market !== "string" ||
    typeof id !== "string" ||
    !client.trim() ||
    !market.trim() ||
    !id.trim()
  ) {
    return res.status(400).json({
      error: "client, market and id are required",
    });
  }

  var processID=generateRandomString(15);
  var accountUUID=generateRandomString(12);

  if (client=="myerror")
  {
    res.status(500).json({
    message: "Internal Servel Error"
  });
  }else{
    res.status(200).json({
    message: "Request accepted",
    data: { client, market, id,processID,accountUUID},
  });

  }

   console.log("===================================================================================================");
  
});


app.post("/api/heavy", authenticate, (req, res) => {
  const { client, market, id } = req.body;

  if (
    typeof client !== "string" ||
    typeof market !== "string" ||
    typeof id !== "string" ||
    !client.trim() ||
    !market.trim() ||
    !id.trim()
  ) {
    return res.status(400).json({
      error: "client, market and id are required",
    });
  }

  var processID=generateRandomString(15);
  var accountUUID=generateRandomString(12);

  // Your route handler logic
  const n = 9000; // Set the number of box objects you want to generate
  const boxes = [];

  for (let i = 0; i < n; i++) {
    boxes.push({
        width: Math.floor(Math.random() * 100) + 1,       // Random integer between 1 and 100
        height: Math.floor(Math.random() * 100) + 1,      // Random integer between 1 and 100
        weight: parseFloat((Math.random() * 50).toFixed(2)), // Random float up to 50.00
        description: `Box-${generateRandomString(8)}`, // Random 8-character string ID
        serial: generateRandomString(4000),   
        content: generateRandomString(4000),
        warehouse: generateRandomString(4000)
    });
}

  res.status(200).json({
    message: "Request accepted",
    data: { client, market, id,processID,accountUUID},
    boxes: boxes
  });
});


app.get("/api/health", (req, res) => {
 
  res.status(200).json({
    message: "API Running" 
  });
});



https.createServer(tlsOptions, app).listen(PORT, () => {
  console.log(`mTLS API listening on port ${PORT}`);
});
