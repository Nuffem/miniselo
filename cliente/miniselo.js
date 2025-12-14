export class Miniselo {
  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  /**
   * Publica uma mensagem.
   * @param {string} chaveBase64 - Chave de 32 bytes em Base64.
   * @param {string} conteudo - Conteúdo da mensagem (máx 512 bytes).
   * @returns {Promise<{id: string}>} - O ID da mensagem publicada.
   */
  async publicar(chaveBase64, conteudo) {
    const res = await fetch(`${this.baseUrl}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chave: chaveBase64, conteúdo: conteudo })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.erro || 'Erro desconhecido ao publicar mensagem.');
    }
    return data;
  }

  /**
   * Obtém uma mensagem pelo ID.
   * @param {string} id - O ID da mensagem.
   * @returns {Promise<string>} - O conteúdo da mensagem.
   */
  async obter(id) {
    const res = await fetch(`${this.baseUrl}/${id}`);
    if (!res.ok) {
      if (res.status === 404) {
        throw new Error('Mensagem não encontrada.');
      }
      throw new Error(`Erro ao obter mensagem: ${res.statusText}`);
    }
    return await res.text();
  }

  /**
   * Gera uma chave aleatória segura de 32 bytes em Base64.
   * @returns {string}
   */
  static gerarChave() {
    const arr = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(arr);
    } else if (typeof require === 'function') {
      const nodeCrypto = require('node:crypto');
      return nodeCrypto.randomBytes(32).toString('base64');
    } else {
      throw new Error('Ambiente não suporta geração de criptografia segura.');
    }

    // Converte Uint8Array para string binária de forma segura
    let binary = '';
    const len = arr.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(arr[i]);
    }

    // btoa is available in modern browsers and Node.js >= 16
    return btoa(binary);
  }
}
