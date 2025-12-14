# Miniselo

Miniselo é um servidor que expõe uma API para publicar mensagens estáticas a partir do navegador com autenticação por HMAC-SHA256.

> **Nota:** Não há garantia de TTL (Time To Live). O servidor pode descartar as mensagens quando necessário (por exemplo, reinício ou limpeza de memória).

## API

### Publicar Mensagem

**Rota:** `POST /`

Cria uma nova mensagem ou atualiza uma existente baseada na chave fornecida.

**Corpo da Requisição (JSON):**

| Campo      | Tipo   | Descrição                                                                 | Restrições                                      |
| :--------- | :----- | :------------------------------------------------------------------------ | :---------------------------------------------- |
| `chave`    | String | A chave secreta do cliente codificada em **Base64**.                      | Deve ter **32 bytes** (decodificada). |
| `conteúdo` | String | O conteúdo da mensagem a ser publicada.                                   | Máximo de **512 bytes**.                        |

**Retorno:**

Retorna o `id` da mensagem, que é o hash **HMAC-SHA256** da chave secreta do cliente. Este `id` é usado para recuperar a mensagem posteriormente.

---

### Ler Mensagem

**Rota:** `GET /<id>`

Recupera o conteúdo de uma mensagem publicada anteriormente.

**Parâmetros de URL:**

| Parâmetro | Descrição                                      |
| :-------- | :--------------------------------------------- |
| `id`      | O hash HMAC-SHA256 retornado na publicação.    |

**Retorno:**

Retorna o conteúdo da mensagem em texto plano (ou conforme o tipo de conteúdo salvo, mas o servidor trata como blob estático).

---

### Ler Documentação

**Rota:** `GET /`

Retorna o conteúdo deste arquivo `LEIA-ME.md`.

## Segurança

Recomenda-se gerar chaves aleatórias para garantir a segurança e unicidade do hash gerado (o `id`).

## Executando com Podman

É possível rodar o servidor utilizando containers (Podman ou Docker). O `ContainerFile` está localizado na pasta `servidor/`.

**1. Construir a imagem:**

Execute o comando na raiz do projeto:

```bash
podman build -t miniselo -f servidor/ContainerFile .
```

**2. Rodar o container:**

```bash
podman run -p 8000:8000 miniselo
```

O servidor estará disponível em `http://localhost:8000`.
