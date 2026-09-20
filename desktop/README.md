# Ethoscan Desktop

Shell Electron mínimo para disparar assessments éticos via a API Ethoscan.

## Pré-requisitos

- API FastAPI em `http://127.0.0.1:8000` (ou URL configurável)
- Redis + worker (`python -m app.worker`)
- Uso **apenas** em alvos autorizados / lab próprio

## Correr

```bash
npm install
npm start
```

Configure a URL base e, se a auth estiver ativa, a mesma `X-API-Key` definida em `ETHOSCAN_API_KEY`.
