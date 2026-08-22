// Worker mTLS SEFAZ — Node 18+ (Express)
// Deploy: Render / Railway / VPS. Start command: node server.js
// Variável de ambiente obrigatória: WORKER_TOKEN (o mesmo token salvo em Configurações)

const express = require("express");
const https = require("node:https");
const forge = require("node-forge");

const app = express();
app.use(express.json({ limit: "20mb" }));

const TOKEN = process.env.WORKER_TOKEN || "";

const ENDPOINTS = {
  producao: { host: "www1.nfe.fazenda.gov.br", path: "/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx" },
  homologacao: { host: "hom1.nfe.fazenda.gov.br", path: "/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx" },
};

function autorizado(req) {
  if (!TOKEN) return true;
  return req.headers.authorization === `Bearer ${TOKEN}`;
}

// Converte PFX (A1) para PEM, suportando algoritmos legados (RC2-40 / 3DES-SHA1).
function pfxParaPem(pfxBase64, senha) {
  const der = forge.util.decode64(pfxBase64);
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, senha);

  let key = null;
  const certs = [];
  for (const safeContents of p12.safeContents) {
    for (const bag of safeContents.safeBags) {
      if (bag.key) key = bag.key;
      if (bag.cert) certs.push(bag.cert);
    }
  }
  if (!key || !certs.length) throw new Error("PFX sem chave privada ou certificado.");

  return {
    key: forge.pki.privateKeyToPem(key),
    cert: certs.map((c) => forge.pki.certificateToPem(c)).join("\n"),
  };
}

function enviarSoap({ ambiente, soap, pfxBase64, senha }) {
  const endpoint = ENDPOINTS[ambiente === "homologacao" ? "homologacao" : "producao"];
  const pem = pfxParaPem(pfxBase64, senha);

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: endpoint.host,
        path: endpoint.path,
        method: "POST",
        key: pem.key,
        cert: pem.cert,
        servername: endpoint.host,
        minVersion: "TLSv1.2",
        headers: {
          "Content-Type": "application/soap+xml; charset=utf-8",
          "Content-Length": Buffer.byteLength(soap),
          "User-Agent": "Mozilla/5.0 (compatible; HubFiscal/1.0)",
        },
        timeout: 60000,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          if (res.statusCode >= 400) reject(new Error(`SEFAZ HTTP ${res.statusCode}: ${body.slice(0, 400)}`));
          else resolve(body);
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("Timeout ao conectar na SEFAZ.")));
    req.on("error", reject);
    req.write(soap);
    req.end();
  });
}

async function handler(req, res) {
  if (!autorizado(req)) return res.status(401).json({ error: "Token inválido." });

  const { ambiente, soap, pfxBase64, senha, probe } = req.body || {};
  if (probe) return res.json({ ok: true });
  if (!soap || !pfxBase64) return res.status(400).json({ error: "Campos 'soap' e 'pfxBase64' são obrigatórios." });

  try {
    const xml = await enviarSoap({ ambiente, soap, pfxBase64, senha });
    res.type("application/xml").send(xml);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

// Aceita também /sefaz/sefaz para instalações que concatenam o caminho configurado.
app.post(["/sefaz", "/sefaz/sefaz", "/nfe", "/proxy", "/dfe", "/"], handler);
app.get(["/health", "/"], (_req, res) => res.json({ ok: true, service: "sefaz-worker" }));

const port = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(port, () => console.log(`sefaz-worker ouvindo na porta ${port}`));
}

module.exports = { app };
