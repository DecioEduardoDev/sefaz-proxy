import express from "express";
import https from "https";

const app = express();
app.use(express.json({ limit: "10mb" })); // Aumentado o limite de payload para suportar arquivos de certificado em Base64

app.post("/sefaz/consulta", (req, res) => {
  // 1. Validação do Token de Segurança da API
  const auth = req.headers["authorization"];
  if (auth !== `Bearer ${process.env.WORKER_TOKEN}`) {
    return res.status(401).json({ erro: "Token invalido" });
  }

  // 2. Extração dinâmica do certificado (Dinamico pelo Body OU Variável de Ambiente global)
  const certBase64 = req.body.pfxBase64 || process.env.SEFAZ_CERT_BASE64;
  const certPassword = req.body.pfxPassword || process.env.SEFAZ_CERT_PASSWORD;

  if (!certBase64) {
    return res.status(400).json({ 
      erro: "Nenhum certificado digital fornecido no corpo da requisicao (pfxBase64) ou no ambiente." 
    });
  }

  // 3. Reconstrói o arquivo .pfx a partir do Base64
  let pfxBuffer;
  try {
    pfxBuffer = Buffer.from(certBase64, "base64");
  } catch (err) {
    return res.status(400).json({ erro: "Falha ao decodificar o certificado Base64 fornecido." });
  }

  // 4. Monta a requisição com mTLS para a SEFAZ do CNPJ específico
  const options = {
    hostname: req.body.hostname,
    port: 443,
    path: req.body.path,
    method: "POST",
    pfx: pfxBuffer,
    passphrase: certPassword,
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
app.listen(PORT, () => console.log(`Proxy SEFAZ Multi-CNPJ rodando na porta ${PORT}`));