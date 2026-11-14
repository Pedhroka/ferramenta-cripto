import base64
import io

from flask import Flask, render_template, request, send_file

from crypto_utils import ErroCriptografia, cifrar, decifrar

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/cifrar")
def rota_cifrar():
    arquivo = request.files.get("arquivo")
    chave = request.files.get("chave_publica")
    if not arquivo or not chave:
        return render_template("index.html", erro="Envie o arquivo e a chave publica."), 400
    try:
        pacote = cifrar(arquivo.read(), chave.read())
    except ErroCriptografia as e:
        return render_template("index.html", erro=str(e)), 400
    return send_file(
        io.BytesIO(pacote),
        mimetype="application/zip",
        as_attachment=True,
        download_name="pacote_cifrado.zip",
    )


@app.post("/decifrar")
def rota_decifrar():
    pacote = request.files.get("pacote")
    chave = request.files.get("chave_privada")
    if not pacote or not chave:
        return render_template("index.html", erro="Envie o pacote e a chave privada."), 400
    try:
        resultado = decifrar(pacote.read(), chave.read())
    except ErroCriptografia as e:
        return render_template("index.html", erro=str(e)), 400
    conteudo_b64 = base64.b64encode(resultado["conteudo"]).decode()
    return render_template("resultado.html", r=resultado, conteudo_b64=conteudo_b64)


@app.errorhandler(413)
def arquivo_grande(_erro):
    return render_template("index.html", erro="Arquivo maior que 20 MB."), 413


if __name__ == "__main__":
    # Roda somente no computador local.
    app.run(host="127.0.0.1", port=5000, debug=False)
