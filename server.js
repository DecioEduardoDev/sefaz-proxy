import express from "express";
import https from "https";

const app = express();
app.use(express.json());

app.post("/sefaz/consulta", (req, res) => {
  const auth = req.headers["authorization"];
  if (auth !== `Bearer ${process.env.WORKER_TOKEN}`) {
    return res.status(401).json({ erro: "Token invalido" });
  }

  if (!process.env.SEFAZ_CERT_BASE64) {
    return res.status(500).json({ erro: "Certificado nao configurado no servidor" });
  }

  // Recompoe o arquivo .pfx a partir do Base64
  const pfxBuffer = Buffer.from(process.env.SEFAZ_CERT_BASE64, "base64");

  const options = {
    hostname: req.body.hostname,
    port: 443,
    path: req.body.path,
    method: "POST",
    pfx: pfxBuffer,
    passphrase: process.env.SEFAZ_CERT_PASSWORD,
    headers: {
      "Content-Type": "application/soap+xml; charset=utf-8",
      ...req.body.headers
    }
  };

  const sefazReq = https.request(options, (sefazRes) => {
    let data = "";
    sefazRes.on("data", (chunk) => (data += chunk));
    sefazRes.on("end", () => res.json({ status: sefazRes.statusCode, body: data }));
  });

  sefazReq.on("error", (err) => res.status(502).json({ erro: err.message }));
  sefazReq.write(req.body.soapEnvelope || "");
  sefazReq.end();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy rodando na porta ${PORT}`));