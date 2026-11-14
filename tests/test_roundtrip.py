import io
import os
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from app import app  # noqa: E402
from crypto_utils import ErroCriptografia, _openssl, cifrar, decifrar  # noqa: E402


def gerar_par_de_chaves(pasta):
    privada = os.path.join(pasta, "privada.pem")
    publica = os.path.join(pasta, "publica.pem")
    subprocess.run([_openssl(), "genpkey", "-algorithm", "RSA",
                    "-pkeyopt", "rsa_keygen_bits:2048", "-out", privada],
                   check=True, capture_output=True)
    subprocess.run([_openssl(), "rsa", "-in", privada, "-pubout", "-out", publica],
                   check=True, capture_output=True)
    with open(privada, "rb") as f:
        priv = f.read()
    with open(publica, "rb") as f:
        pub = f.read()
    return priv, pub


@pytest.fixture(scope="module")
def chaves(tmp_path_factory):
    return gerar_par_de_chaves(tmp_path_factory.mktemp("chaves"))


@pytest.fixture(scope="module")
def outras_chaves(tmp_path_factory):
    return gerar_par_de_chaves(tmp_path_factory.mktemp("outras"))


def test_roundtrip_texto_pequeno(chaves):
    priv, pub = chaves
    original = b"Mensagem de teste da ferramenta de criptografia."
    resultado = decifrar(cifrar(original, pub), priv)
    assert resultado["conteudo"] == original
    assert resultado["confere"] is True


def test_roundtrip_arquivo_grande(chaves):
    # Um arquivo de 3 MB seria inviavel para RSA direto; o AES cifra sem problema.
    priv, pub = chaves
    original = os.urandom(3 * 1024 * 1024)
    resultado = decifrar(cifrar(original, pub), priv)
    assert resultado["conteudo"] == original
    assert resultado["confere"] is True


def test_chave_privada_errada_falha(chaves, outras_chaves):
    priv_certa, pub = chaves
    priv_errada, _ = outras_chaves
    pacote = cifrar(b"segredo", pub)
    with pytest.raises(ErroCriptografia):
        decifrar(pacote, priv_errada)


def test_pacote_invalido_falha(chaves):
    priv, _ = chaves
    with pytest.raises(ErroCriptografia):
        decifrar(b"isto nao e um zip", priv)


def test_rota_web_roundtrip(chaves):
    priv, pub = chaves
    original = b"Teste pela interface web."
    client = app.test_client()

    resposta_cifra = client.post(
        "/cifrar",
        data={
            "arquivo": (io.BytesIO(original), "teste.txt"),
            "chave_publica": (io.BytesIO(pub), "publica.pem"),
        },
        content_type="multipart/form-data",
    )
    assert resposta_cifra.status_code == 200
    pacote = resposta_cifra.data

    resposta_decifra = client.post(
        "/decifrar",
        data={
            "pacote": (io.BytesIO(pacote), "pacote_cifrado.zip"),
            "chave_privada": (io.BytesIO(priv), "privada.pem"),
        },
        content_type="multipart/form-data",
    )
    assert resposta_decifra.status_code == 200
    assert "Os hashes conferem" in resposta_decifra.get_data(as_text=True)
