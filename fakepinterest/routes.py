# criar as rotas do nosso site ( os links)
from flask import render_template, url_for, redirect, request
from fakepinterest import app, database, bcrypt
from fakepinterest.models import Usuario, Foto
from flask_login import login_required, login_user, logout_user, current_user
from fakepinterest.forms import FormLogin, FormCriarConta, FormFoto
import os
from werkzeug.utils import secure_filename
from flask import flash

@app.route("/", methods=["GET", "POST"])
def homepage():
    form_login = FormLogin()
    if form_login.validate_on_submit():
        usuario = Usuario.query.filter_by(email=form_login.email.data).first()
        if usuario and bcrypt.check_password_hash(usuario.senha.encode("utf-8"), form_login.senha.data):
            login_user(usuario)
            return redirect(url_for("perfil", id_usuario=usuario.id))
    return render_template("homepage.html", form=form_login)

@app.route("/criarconta", methods=["GET", "POST"])
def criar_conta():
    form_criarconta = FormCriarConta()
    if form_criarconta.validate_on_submit():
        senha = bcrypt.generate_password_hash(form_criarconta.senha.data).decode("utf-8")
        usuario = Usuario(username=form_criarconta.username.data,
                          senha=senha, email=form_criarconta.email.data)
        database.session.add(usuario)
        database.session.commit()
        login_user(usuario, remember=True)
        return redirect(url_for("perfil", id_usuario=usuario.id))
    return render_template("criarconta.html", form=form_criarconta)

@app.route("/perfil/<id_usuario>", methods=["GET", "POST"])
@login_required
def perfil(id_usuario):
    if int(id_usuario) == int(current_user.id):
        # o usuario vendo o perfil dele
        form_foto = FormFoto()
        if form_foto.validate_on_submit():
            arquivo = form_foto.foto.data
            nome_seguro = secure_filename(arquivo.filename)
            # salvar o arquivo na pasta fotos_post
            caminho = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                              app.config["UPLOAD_FOLDER"], nome_seguro)
            arquivo.save(caminho)
            # registrar esse arquivo no banco de dados
            foto = Foto(imagem=nome_seguro, id_usuario=current_user.id)
            database.session.add(foto)
            database.session.commit()
        return render_template("perfil.html", usuario=current_user, form=form_foto)
    else:
        usuario = Usuario.query.get(int(id_usuario))
        return render_template("perfil.html", usuario=usuario, form=None)


@app.route("/perfil/<id_usuario>/excluir_imagem", methods=["GET", "POST"])
@login_required
def excluir_imagem(id_usuario):
    if int(id_usuario) == int(current_user.id):
        if 'nome_imagem' in request.form:
            nome_seguro = request.form['nome_imagem']
            try:
                # Remova a referência da imagem do banco de dados
                foto = Foto.query.filter_by(imagem=nome_seguro, id_usuario=current_user.id).first()
                if foto:
                    database.session.delete(foto)
                    database.session.commit()
                    # Exclua a imagem do sistema de arquivos
                    caminho_imagem = os.path.join(app.config["UPLOAD_FOLDER"], nome_seguro)
                    if os.path.exists(caminho_imagem):
                        os.remove(caminho_imagem)
                        flash("Imagem excluída com sucesso!", "success")
                    else:
                        flash("Imagem não encontrada no sistema de arquivos.", "error")
                else:
                    flash("Imagem não encontrada no banco de dados.", "error")
            except Exception as e:
                flash(f"Erro ao excluir a imagem: {str(e)}", "error")
        else:
            flash("Nome da imagem não fornecido.", "error")
    else:
        flash("Você não tem permissão para excluir esta imagem.", "error")

    return redirect(url_for("perfil", id_usuario=id_usuario))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("homepage"))

#o valor entre conchete é numero de fotos que vai aparecer
@app.route("/feed")
@login_required
def feed():
    fotos = Foto.query.order_by(Foto.data_criacao.desc()).all()[:20]
    return render_template("feed.html", fotos=fotos)