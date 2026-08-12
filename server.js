// server.js
import express from "express";
import https from "https";
import fs from "fs";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Variáveis de ambiente no painel da Render/Railway:
//   SEFAZ_CERT_BASE64  → certificado .pfx em Base64
//   SEFAZ_CERT_PASSWORD → senha do .pfx
//   WORKER_TOKEN       → token que você inventa (o app enviará este token)

app.post("/sefaz/consulta", (req, res) => {
  const auth = req.headers["authorization"];
  if (auth !== `Bearer ${process.env.WORKER_TOKEN}`) {
    return res.status(401).json({ erro: "Token inválido" });
  }

  // Reconstrói o .pfx a partir do Base64
  const pfxBuffer = Buffer.from(process.env.SEFAZ_CERT_BASE64, "base64");

  // Monta a requisição SOAP para a SEFAZ com mTLS
  const options = {
    hostname: req.body.hostname,  // ex: "nfe-homologacao.sefazrs.rs.gov.br"
    port: 443,
    path: req.body.path,
    method: "POST",
    pfx: pfxBuffer,
    passphrase: process.env.SEFAZ_CERT_PASSWORD,
    headers: { "Content-Type": "application/soap+xml; charset=utf-8", ...req.body.headers },
    body: req.body.soapEnvelope,
  };

  const sefazReq = https.request(options, (sefazRes) => {
    let data = "";
    sefazRes.on("data", (chunk) => (data += chunk));
    sefazRes.on("end", () => res.json({ status: sefazRes.statusCode, body: data }));
  });

  sefazReq.on("error", (err) => res.status(502).json({ erro: err.message }));
  sefazReq.write(req.body.soapEnvelope);
  sefazReq.end();
});

app.listen(process.env.PORT || 3000);
