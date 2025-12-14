const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const PORT = process.env.PORT || 8000;

const KEY_PATH = path.join(os.homedir(), '.miniselo_server_key');
let serverKey;

try {
  if (fs.existsSync(KEY_PATH)) {
    serverKey = fs.readFileSync(KEY_PATH);
    if (serverKey.length !== 32) {
      console.log('Chave do servidor inválida encontrada. Gerando nova chave...');
      serverKey = crypto.randomBytes(32);
      fs.writeFileSync(KEY_PATH, serverKey, { mode: 0o600 });
    }
  } else {
    serverKey = crypto.randomBytes(32);
    fs.writeFileSync(KEY_PATH, serverKey, { mode: 0o600 });
  }
} catch (err) {
  console.error('Erro ao acessar a chave do servidor:', err);
  process.exit(1);
}

// Armazenamento em memória (volátil)
const database = new Map();

// Carregar documentação na memória
const readmePath = path.join(__dirname, '..', 'LEIA-ME.md');
let readmeContent = 'Miniselo API - Documentação não encontrada.';
try {
  readmeContent = fs.readFileSync(readmePath, 'utf8');
} catch (err) {
  console.error('Erro ao carregar LEIA-ME.md:', err.message);
}

const server = http.createServer((req, res) => {
  // Configuração de CORS para permitir acesso via navegador
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Pre-flight request
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Endpoint: POST /
  if (req.method === 'POST' && req.url === '/') {
    let body = '';

    req.on('data', chunk => {
      body += chunk;
      // Limite de segurança simples para evitar flood de memória ( ~10KB )
      if (body.length > 1024 * 10) {
        req.destroy();
      }
    });

    req.on('end', () => {
      if (req.destroyed) return;

      try {
        if (!body) throw new Error("Body vazio");
        const data = JSON.parse(body);

        // Validações
        const { chave, conteúdo } = data;

        if (!chave || typeof chave !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ erro: 'Campo "chave" é obrigatório e deve ser uma string Base64.' }));
        }

        if (!conteúdo || typeof conteúdo !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ erro: 'Campo "conteúdo" é obrigatório e deve ser uma string.' }));
        }

        // Decodificar Base64 e verificar tamanho (32 bytes)
        const keyBuffer = Buffer.from(chave, 'base64');
        if (keyBuffer.length !== 32) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ erro: 'A chave deve ter exatamente 32 bytes (quando decodificada).' }));
        }

        // Verificar tamanho do conteúdo (máx 512 bytes)
        if (Buffer.byteLength(conteúdo) > 512) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ erro: 'O conteúdo excede o limite de 512 bytes.' }));
        }

        // Gerar ID: HMAC-SHA256 usando a chave do servidor (key) e a chave do cliente (data)
        const id = crypto.createHmac('sha256', serverKey)
          .update(keyBuffer)
          .digest('base64url');

        // Salvar ou atualizar
        database.set(id, conteúdo);

        // Sucesso
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id }));

      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ erro: 'Requisição inválida (JSON malformado ou erro interno).' }));
      }
    });
    return;
  }

  // Endpoint: GET /<id>
  // Verifica se a URL corresponde a um hash SHA256 em base64url (43 caracteres)
  const match = req.url.match(/^\/([a-zA-Z0-9\-_]{43})$/);
  if (req.method === 'GET' && match) {
    const id = match[1];

    if (database.has(id)) {
      const content = database.get(id);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(content);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Mensagem não encontrada');
    }
    return;
  }

  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(readmeContent);
    return;
  }

  // Tratamento para rotas não encontradas
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ erro: 'Endpoint não encontrado.' }));
});

server.listen(PORT, () => {
  console.log(`Servidor Miniselo rodando na porta ${PORT}`);
});
