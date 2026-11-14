# Ferramenta de criptografia hibrida

Aplicacao Flask que cifra e decifra documentos com OpenSSL: AES-256-CBC para o conteudo e RSA-2048 para proteger a chave AES.

Uso educacional, rodando somente em localhost com arquivos de teste.

## Requisitos
- Python 3.10 ou superior
- OpenSSL (no Git for Windows, em `C:\Program Files\Git\ucrt64\bin\openssl.exe`). Se estiver em outro lugar, defina a variavel `OPENSSL_BIN` com o caminho completo.

## Instalacao
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Testes
```
python -m pytest -v
```

## Executar
```
python app.py
```
Abra http://127.0.0.1:5000 no navegador.

## Chaves
As chaves nao ficam no repositorio. Gere-as fora da pasta do projeto:
```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privada.pem
openssl rsa -in privada.pem -pubout -out publica.pem
```
Use `publica.pem` para cifrar e `privada.pem` para decifrar.
