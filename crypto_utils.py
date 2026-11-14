"""Criptografia hibrida com OpenSSL.

AES-256-CBC cifra o conteudo (rapido, sem limite pratico de tamanho).
RSA cifra apenas a chave AES de 32 bytes (envelope digital).
"""

import hashlib
import io
import os
import shutil
import subprocess
import tempfile
import zipfile

# No Git for Windows o openssl fica em ucrt64\bin, que nao esta no PATH por padrao.
# Para usar outro caminho, defina a variavel de ambiente OPENSSL_BIN.
DEFAULT_OPENSSL = r"C:\Program Files\Git\ucrt64\bin\openssl.exe"

# RSA-OAEP com SHA-256. A atividade pede "openssl pkeyutl -encrypt";
# OAEP e o padding recomendado para uso real.
RSA_OAEP = ["-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256"]

PACOTE_ARQUIVOS = ("mensagem.enc", "chave_aes.enc", "sha256_original.txt")


class ErroCriptografia(Exception):
    """Erro esperado de cifragem ou decifragem (chave errada, pacote invalido etc.)."""


def _openssl():
    return os.environ.get("OPENSSL_BIN") or shutil.which("openssl") or DEFAULT_OPENSSL


def _executar(args, env=None):
    resultado = subprocess.run([_openssl(), *args], capture_output=True, env=env)
    if resultado.returncode != 0:
        msg = resultado.stderr.decode(errors="replace").strip()
        raise ErroCriptografia(f"OpenSSL falhou: {msg}")
    return resultado


def sha256(dados: bytes) -> str:
    return hashlib.sha256(dados).hexdigest()


def cifrar(conteudo: bytes, chave_publica: bytes) -> bytes:
    """Cifra o conteudo para o dono da chave publica.

    Retorna um ZIP com mensagem.enc, chave_aes.enc e sha256_original.txt.
    """
    chave_aes = os.urandom(32)  # 32 bytes = AES-256

    with tempfile.TemporaryDirectory() as tmp:
        def caminho(nome):
            return os.path.join(tmp, nome)

        with open(caminho("publica.pem"), "wb") as f:
            f.write(chave_publica)
        with open(caminho("mensagem.txt"), "wb") as f:
            f.write(conteudo)
        with open(caminho("chave_aes.bin"), "wb") as f:
            f.write(chave_aes)

        # A senha vai por variavel de ambiente, para nao aparecer na lista de processos.
        env = {**os.environ, "AES_PASS": chave_aes.hex()}
        _executar(["enc", "-aes-256-cbc", "-pbkdf2", "-salt",
                   "-in", caminho("mensagem.txt"), "-out", caminho("mensagem.enc"),
                   "-pass", "env:AES_PASS"], env=env)

        _executar(["pkeyutl", "-encrypt", "-pubin", "-inkey", caminho("publica.pem"),
                   "-in", caminho("chave_aes.bin"), "-out", caminho("chave_aes.enc"),
                   *RSA_OAEP])

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(caminho("mensagem.enc"), "mensagem.enc")
            zf.write(caminho("chave_aes.enc"), "chave_aes.enc")
            zf.writestr("sha256_original.txt", sha256(conteudo) + "\n")
        return buffer.getvalue()


def decifrar(pacote_zip: bytes, chave_privada: bytes) -> dict:
    """Decifra um pacote gerado por cifrar().

    Retorna o conteudo recuperado e os dois hashes SHA-256 para comparacao.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(pacote_zip))
    except zipfile.BadZipFile as e:
        raise ErroCriptografia("O pacote enviado nao e um arquivo ZIP valido.") from e

    with zf:
        if any(nome not in zf.namelist() for nome in PACOTE_ARQUIVOS):
            raise ErroCriptografia("O pacote nao contem os arquivos esperados.")
        mensagem_enc = zf.read("mensagem.enc")
        chave_enc = zf.read("chave_aes.enc")
        hash_original = zf.read("sha256_original.txt").decode().strip()

    with tempfile.TemporaryDirectory() as tmp:
        def caminho(nome):
            return os.path.join(tmp, nome)

        with open(caminho("privada.pem"), "wb") as f:
            f.write(chave_privada)
        with open(caminho("mensagem.enc"), "wb") as f:
            f.write(mensagem_enc)
        with open(caminho("chave_aes.enc"), "wb") as f:
            f.write(chave_enc)

        _executar(["pkeyutl", "-decrypt", "-inkey", caminho("privada.pem"),
                   "-in", caminho("chave_aes.enc"), "-out", caminho("chave_aes.bin"),
                   *RSA_OAEP])

        with open(caminho("chave_aes.bin"), "rb") as f:
            chave_aes = f.read()

        env = {**os.environ, "AES_PASS": chave_aes.hex()}
        _executar(["enc", "-d", "-aes-256-cbc", "-pbkdf2",
                   "-in", caminho("mensagem.enc"), "-out", caminho("restaurado.txt"),
                   "-pass", "env:AES_PASS"], env=env)

        with open(caminho("restaurado.txt"), "rb") as f:
            conteudo = f.read()

    hash_restaurado = sha256(conteudo)
    return {
        "conteudo": conteudo,
        "sha256_original": hash_original,
        "sha256_restaurado": hash_restaurado,
        "confere": hash_restaurado == hash_original,
    }
