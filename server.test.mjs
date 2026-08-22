import test from 'node:test';
import assert from 'node:assert/strict';
import { app } from './server.js';

process.env.WORKER_TOKEN = 'test-token';
process.env.SEFAZ_CERT_BASE64 = Buffer.from('fake-cert').toString('base64');

const publicBaseUrl = process.env.PUBLIC_BASE_URL || 'https://meu-sefaz-proxy.onrender.com';

test('POST /sefaz should accept a request at the public URL', async () => {
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));

  const { port } = server.address();
  const localBaseUrl = `http://127.0.0.1:${port}`;

  try {
    const requestUrl = `${localBaseUrl}/sefaz`;
    const response = await fetch(requestUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-token',
      },
      body: JSON.stringify({
        hostname: 'example.com',
        path: '/ws',
        soapEnvelope: '<Envelope />',
      }),
    });

    assert.notEqual(response.status, 404, 'A rota /sefaz deve existir localmente');
    assert.equal(new URL(`${publicBaseUrl}/sefaz`).pathname, '/sefaz');
  } finally {
    server.close();
  }
});

test('POST /sefaz/sefaz remains available for duplicated worker URLs', async () => {
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));

  const { port } = server.address();

  try {
    const response = await fetch(`http://127.0.0.1:${port}/sefaz/sefaz`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-token',
      },
      body: JSON.stringify({ probe: true }),
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true });
  } finally {
    server.close();
  }
});
