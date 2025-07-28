from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import csv
import requests
from math import pow
from sqlalchemy import desc
from dateutil.relativedelta import relativedelta
import pytz
import pandas as pd
from werkzeug.utils import secure_filename
from sqlalchemy.dialects.sqlite import JSON
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from sqlalchemy.orm import joinedload
from bs4 import BeautifulSoup
from bs4.element import Tag
from sqlalchemy import func
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'uma-chave-secreta-muito-segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contratos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config['SESSION_PERMANENT'] = False  # Session expires when browser closes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session lifetime

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ===================== MODELOS =====================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def verify_password(self, password_input):
        return check_password_hash(self.password, password_input)

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

class Contrato(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contrato = db.Column(db.String(50), unique=True, nullable=False)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=False)
    empresa = db.relationship('Empresa', backref=db.backref('contratos', lazy=True))
    produto_id = db.Column(db.Integer, db.ForeignKey('produto.id'), nullable=True)
    produto = db.relationship('Produto', backref=db.backref('contratos', lazy=True))
    instituicao = db.Column(db.String(100), nullable=False)
    inicio = db.Column(db.Date, nullable=False)
    saldo_inicial = db.Column(db.Numeric(15, 2), nullable=False)
    saldo_devedor = db.Column(db.Numeric(15, 2), nullable=True)
    indexador = db.Column(db.String(50))
    juros_pre = db.Column(db.Numeric(10, 4))
    juros_spread = db.Column(db.Numeric(10, 4))
    juros_anual = db.Column(db.Numeric(10, 4))
    juros_mensal = db.Column(db.Numeric(15, 10), nullable=True)
    parcela = db.Column(db.Numeric(15, 2))
    qtd_parcela = db.Column(db.Integer)
    parc_paga = db.Column(db.Integer, default=0)
    parc_pendente = db.Column(db.Integer)
    principal_pago = db.Column(db.Numeric(15, 2), default=0)
    principal_pendente = db.Column(db.Numeric(15, 2))
    juros_pago = db.Column(db.Numeric(15, 2), default=0)
    juros_pendente = db.Column(db.Numeric(15, 2))
    curto_pz = db.Column(db.Numeric(15, 2))
    longo_pz = db.Column(db.Numeric(15, 2))
    erp = db.Column(db.String(50))
    carencia_juros = db.Column(db.Integer, default=0)
    carencia_principal = db.Column(db.Integer, default=0)
    prazo_meses = db.Column(db.Integer)
    data_rescisao = db.Column(db.Date)
    data_assinatura = db.Column(db.Date)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    tipo_contrato = db.Column(db.String(20))
    iof = db.Column(db.Numeric(15, 2), default=0)
    tac = db.Column(db.Numeric(15, 2), default=0)
    outros = db.Column(db.Numeric(15, 2), default=0)
    modalidade = db.Column(db.String(50))
    sistema_amortizacao = db.Column(db.String(50))
    customizado_amortizacao = db.Column(JSON, nullable=True)

class TaxaReferencia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False)
    valor = db.Column(db.String(20), nullable=False)
    data_atualizacao = db.Column(db.DateTime, default=datetime.utcnow)
   
    

class LogSistema(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50))
    acao = db.Column(db.String(50))
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)
    detalhes = db.Column(db.Text)
    ip = db.Column(db.String(50))

from werkzeug.security import generate_password_hash, check_password_hash

# ===================== FUNÇÕES AUXILIARES =====================
def format_taxa_percentual(taxa_decimal, casas_decimais=10):
    """Formata taxa decimal para percentual com precisão consistente"""
    try:
        if isinstance(taxa_decimal, Decimal):
            return f"{taxa_decimal * 100:.{casas_decimais}f}%"
        else:
            return f"{Decimal(str(taxa_decimal)) * 100:.{casas_decimais}f}%"
    except:
        return "0.0000000000%"

# --- Login Manager ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))




# --- Helper Functions ---
def parse_date_or_none(date_str):
    if date_str:
        try:
            return datetime.strptime(date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            return None
    return None

def to_float_or_none(value):
    try:
        return float(value) if value else None
    except (ValueError, TypeError):
        return None

def to_int_or_none(value):
    try:
        return int(value) if value else None
    except (ValueError, TypeError):
        return None

def safe_decimal(val):
    try:
        if val is None or val == '':
            return Decimal('0.00')
        if isinstance(val, str):
            # Converte apenas vírgula para ponto (formato brasileiro)
            val = val.replace(',', '.')
        return Decimal(val)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal('0.00')

# --- Routes ---
@app.route('/')
@login_required
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query_args = request.args.to_dict()
    query_args.pop('page', None)

    # INÍCIO DOS FILTROS
    query = Contrato.query

    instituicao = request.args.get('instituicao')
    if instituicao and instituicao.strip() not in ('', 'todas', 'Todos'):
        query = query.filter(Contrato.instituicao.ilike(f"%{instituicao.strip()}%"))

    produto = request.args.get('produto')
    if produto and produto not in ('', 'todos', 'Todos'):
        query = query.filter(Contrato.produto == produto)

    modalidade = request.args.get('modalidade')
    if modalidade and modalidade not in ('', 'todas', 'Todas'):
        query = query.filter(Contrato.modalidade == modalidade)

    status = request.args.get('status')
    if status == 'ativos':
        query = query.filter(Contrato.parc_pendente > 0)
    elif status == 'quitados':
        query = query.filter(Contrato.parc_pendente == 0)

    numero_contrato = request.args.get('numero_contrato')
    if numero_contrato and numero_contrato.strip() != '':
        query = query.filter(Contrato.contrato.contains(numero_contrato))

    ano = request.args.get('ano')
    if ano and ano.strip() != '':
        try:
            query = query.filter(db.extract('year', Contrato.inicio) == int(ano))
        except ValueError:
            pass

    mes = request.args.get('mes')
    if mes and mes.strip() != '':
        try:
            query = query.filter(db.extract('month', Contrato.inicio) == int(mes))
        except ValueError:
            pass
    # FIM DOS FILTROS

    contratos = query.options(joinedload(Contrato.empresa)).outerjoin(Empresa).order_by(Empresa.nome, Contrato.inicio)\
                    .paginate(page=page, per_page=per_page, error_out=False)

    # Calcular saldo devedor para cada contrato
    contratos_lista = []
    for c in contratos.items:
        try:
            resultado = calcular_parcelas(c)
            parcelas = resultado['parcelas']
            principal_pago = sum(p['amortizacao'] for i, p in enumerate(parcelas[:c.parc_paga or 0])) if parcelas else 0
            principal_pendente = sum(p['amortizacao'] for i, p in enumerate(parcelas[c.parc_paga or 0:])) if parcelas else float(c.saldo_inicial or 0)
            juros_pago = sum(p['pgto_juros'] for i, p in enumerate(parcelas[:c.parc_paga or 0])) if parcelas else 0
            juros_pendente = sum(p['pgto_juros'] for i, p in enumerate(parcelas[c.parc_paga or 0:])) if parcelas else 0
            saldo_devedor = principal_pendente + juros_pendente
        except Exception:
            saldo_devedor = c.saldo_devedor or 0
        c.saldo_devedor_calculado = saldo_devedor
        # Garantir que juros_mensal seja Decimal
        if c.juros_mensal is not None and not isinstance(c.juros_mensal, Decimal):
            c.juros_mensal = Decimal(str(c.juros_mensal))
        contratos_lista.append(c)

    total_contratos = Contrato.query.count()
    contratos_ativos = Contrato.query.filter(Contrato.parc_pendente > 0).count()
    vencimento_curto = db.session.query(db.func.sum(Contrato.curto_pz)).scalar() or 0
    inadimplentes = 0

    filtros = {
      'numero_contrato': request.args.get('numero_contrato', ''),
      'ano': request.args.get('ano', ''),
      'mes': request.args.get('mes', '')
    }

    return render_template('index.html',
        contratos=contratos_lista,
        pagination=contratos,
        total_contratos=total_contratos,
        contratos_ativos=contratos_ativos,
        vencimento_curto=vencimento_curto,
        inadimplentes=inadimplentes,
        filtros=filtros,
        query_args=query_args
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            registrar_log('login', f'Usuário {user.username} fez login')
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))  # ou qualquer página inicial
        else:
            flash('Usuário ou senha incorretos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    registrar_log('logout', f'Usuário {current_user.username} fez logout')
    logout_user()
    flash('Você foi desconectado com sucesso.', 'info')
    return redirect(url_for('login'))

@app.route('/usuarios')
@login_required
def listar_usuarios():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('index'))
    
    usuarios = User.query.order_by(User.created_at.desc()).all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/cadastrar-usuario', methods=['GET', 'POST'])
@login_required
def cadastrar_usuario():
    if not current_user.is_admin:
        flash('Apenas administradores podem cadastrar novos usuários.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if not username or not password:
            flash('Nome de usuário e senha são obrigatórios.', 'danger')
            return redirect(url_for('cadastrar_usuario'))
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Nome de usuário já está em uso.', 'danger')
            return redirect(url_for('cadastrar_usuario'))
        
        try:
            new_user = User(
                username=username,
                password=generate_password_hash(password),  # <<< FAZENDO HASH CORRETAMENTE
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar usuário: {str(e)}', 'danger')
    
    return render_template('cadastro.html')

@app.route('/editar-usuario/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if not current_user.is_admin:
        flash('Apenas administradores podem editar usuários.', 'danger')
        return redirect(url_for('index'))
    
    usuario = User.query.get_or_404(id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        # Verifica se o username já existe (exceto para o próprio usuário)
        existing_user = User.query.filter(User.username == username, User.id != id).first()
        if existing_user:
            flash('Nome de usuário já está em uso por outro usuário.', 'danger')
            return redirect(url_for('editar_usuario', id=id))
        
        try:
            usuario.username = username
            usuario.is_admin = is_admin
            
            # Só atualiza a senha se foi fornecida uma nova
            if password:
                usuario.password = generate_password_hash(password)
            
            db.session.commit()
            flash('Usuário atualizado com sucesso!', 'success')
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar usuário: {str(e)}', 'danger')
    
    return render_template('editar_usuario.html', usuario=usuario)

@app.route('/excluir-usuario/<int:id>')
@login_required
def excluir_usuario(id):
    if not current_user.is_admin:
        flash('Apenas administradores podem excluir usuários.', 'danger')
        return redirect(url_for('index'))
    
    if current_user.id == id:
        flash('Você não pode excluir a si mesmo.', 'danger')
        return redirect(url_for('listar_usuarios'))
    
    usuario = User.query.get_or_404(id)
    try:
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir usuário: {str(e)}', 'danger')
    
    return redirect(url_for('listar_usuarios'))

@app.route('/produtos')
@login_required
def listar_produtos():
    produtos = Produto.query.order_by(Produto.nome).all()
    return render_template('produtos.html', produtos=produtos)

@app.route('/cadastrar-produto', methods=['GET', 'POST'])
@login_required
def cadastrar_produto():
    if request.method == 'POST':
        nome = request.form.get('nome')
        if not nome:
            flash('Nome do produto é obrigatório.', 'danger')
            return redirect(url_for('cadastrar_produto'))
        if Produto.query.filter_by(nome=nome).first():
            flash('Produto já cadastrado.', 'danger')
            return redirect(url_for('cadastrar_produto'))
        produto = Produto(nome=nome)
        db.session.add(produto)
        db.session.commit()
        flash('Produto cadastrado com sucesso!', 'success')
        return redirect(url_for('listar_produtos'))
    return render_template('cadastro_produto.html')

@app.route('/produto/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_produto(id):
    produto = Produto.query.get_or_404(id)
    db.session.delete(produto)
    db.session.commit()
    flash('Produto excluído com sucesso!', 'success')
    return redirect(url_for('listar_produtos'))

@app.route('/contrato/novo', methods=['GET', 'POST'])
@login_required
def novo_contrato():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    produtos = Produto.query.order_by(Produto.nome).all()
    empresas = Empresa.query.order_by(Empresa.nome).all()
    if request.method == 'POST':
        try:
            print(f"DEBUG FORM - Valor bruto recebido de juros_mensal: {request.form.get('juros_mensal')}")
            contrato_num = request.form.get('contrato')
            if not contrato_num:
                flash('Número do contrato é obrigatório', 'danger')
                return redirect(request.url)
            existing = Contrato.query.filter_by(contrato=contrato_num).first()
            if existing:
                flash('Contrato já existe.', 'danger')
                return redirect(request.url)
            # Garantir que pelo menos qtd_parcela ou prazo_meses seja preenchido
            qtd_parcela = to_int_or_none(request.form.get('qtd_parcela'))
            prazo_meses = to_int_or_none(request.form.get('prazo_meses'))
            if not qtd_parcela and not prazo_meses:
                flash('Preencha o Total de Parcelas ou o Prazo Total (meses).', 'danger')
                return redirect(request.url)
            def zero_if_none(val):
                return val if val is not None else 0
            customizado_amortizacao = request.form.get('customizado_amortizacao')
            customizado_amortizacao_val = parse_customizado_amortizacao(customizado_amortizacao)
            if customizado_amortizacao and customizado_amortizacao_val is None:
                flash('Formato inválido para amortização customizada. Use uma lista de percentuais, ex: 10,20,30,40', 'danger')
                return redirect(request.url)
            # Preencher juros_mensal automaticamente se não informado
            juros_mensal = parse_decimal_field('juros_mensal', percent_to_decimal=True)
            print(f"DEBUG - Juros Mensal recebido (novo): {juros_mensal}")
            contrato = Contrato(
                contrato=contrato_num,
                empresa_id=request.form.get('empresa_id'),
                produto_id=request.form.get('produto_id'),
                instituicao=request.form.get('instituicao'),
                inicio=parse_date_or_none(request.form.get('inicio')),
                saldo_inicial=zero_if_none(to_float_or_none(request.form.get('saldo_inicial'))),
                saldo_devedor=zero_if_none(to_float_or_none(request.form.get('saldo_devedor'))),
                indexador=request.form.get('indexador'),
                juros_pre=zero_if_none(to_float_or_none(request.form.get('juros_pre'))),
                juros_spread=zero_if_none(to_float_or_none(request.form.get('juros_spread'))),
                juros_anual=zero_if_none(to_float_or_none(request.form.get('juros_anual'))),
                juros_mensal=zero_if_none(juros_mensal),
                parcela=zero_if_none(to_float_or_none(request.form.get('parcela'))),
                qtd_parcela=zero_if_none(qtd_parcela),
                parc_pendente=zero_if_none(qtd_parcela),
                principal_pendente=zero_if_none(to_float_or_none(request.form.get('saldo_inicial'))),
                carencia_juros=zero_if_none(to_int_or_none(request.form.get('carencia_juros'))),
                carencia_principal=zero_if_none(to_int_or_none(request.form.get('carencia_principal'))),
                prazo_meses=zero_if_none(prazo_meses),
                erp=request.form.get('erp'),
                tipo_contrato=request.form.get('tipo_juros'),
                data_rescisao=parse_date_or_none(request.form.get('data_rescisao')),
                iof=zero_if_none(to_float_or_none(request.form.get('iof'))),
                tac=zero_if_none(to_float_or_none(request.form.get('tac'))),
                outros=zero_if_none(to_float_or_none(request.form.get('outros'))),
                modalidade=request.form.get('modalidade'),
                sistema_amortizacao=request.form.get('sistema_amortizacao'),
                customizado_amortizacao=customizado_amortizacao_val,
                data_assinatura=parse_date_or_none(request.form.get('data_assinatura'))
            )
            db.session.add(contrato)
            db.session.commit()
            registrar_log('adicionar_contrato', f'Contrato {contrato.contrato} adicionado')
            flash('Contrato cadastrado com sucesso!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar contrato: {str(e)}', 'danger')
    return render_template('form_contrato.html', produtos=produtos, empresas=empresas)

@app.route('/contrato/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_contrato(id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    contrato = Contrato.query.get_or_404(id)
    produtos = Produto.query.order_by(Produto.nome).all()
    empresas = Empresa.query.order_by(Empresa.nome).all()
    if request.method == 'POST':
        try:
            print(f"DEBUG FORM - Valor bruto recebido de juros_mensal: {request.form.get('juros_mensal')}")
            # Usar a função global parse_decimal_field
            valor = parse_decimal_field('saldo_inicial')
            print(f"DEBUG - Saldo Inicial recebido: {valor}")
            if valor is not None:
                contrato.saldo_inicial = valor
            valor = parse_decimal_field('saldo_devedor')
            if valor is not None:
                contrato.saldo_devedor = valor
            valor = parse_decimal_field('parcela')
            if valor is not None:
                contrato.parcela = valor
            valor = parse_decimal_field('iof')
            if valor is not None:
                contrato.iof = valor
            valor = parse_decimal_field('tac')
            if valor is not None:
                contrato.tac = valor
            valor = parse_decimal_field('outros')
            if valor is not None:
                contrato.outros = valor
            valor = parse_decimal_field('juros_pre')
            if valor is not None:
                contrato.juros_pre = valor
            valor = parse_decimal_field('juros_anual')
            if valor is not None:
                contrato.juros_anual = valor
            valor = parse_decimal_field('principal_pago')
            if valor is not None:
                contrato.principal_pago = valor
            valor = parse_decimal_field('principal_pendente')
            if valor is not None:
                contrato.principal_pendente = valor
            valor = parse_decimal_field('juros_pago')
            if valor is not None:
                contrato.juros_pago = valor
            valor = parse_decimal_field('juros_pendente')
            if valor is not None:
                contrato.juros_pendente = valor
            valor = parse_decimal_field('curto_pz')
            if valor is not None:
                contrato.curto_pz = valor
            valor = parse_decimal_field('longo_pz')
            if valor is not None:
                contrato.longo_pz = valor
            valor = parse_int_field('qtd_parcela')
            if valor is not None:
                contrato.qtd_parcela = valor
            valor = parse_int_field('parc_paga')
            if valor is not None:
                contrato.parc_paga = valor
            valor = parse_int_field('parc_pendente')
            if valor is not None:
                contrato.parc_pendente = valor
            valor = parse_int_field('carencia_juros')
            if valor is not None:
                contrato.carencia_juros = valor
            valor = parse_int_field('carencia_principal')
            if valor is not None:
                contrato.carencia_principal = valor
            valor = parse_int_field('prazo_meses')
            if valor is not None:
                contrato.prazo_meses = valor
            # Regras de juros conforme modalidade
            modalidade = request.form.get('modalidade')
            contrato.modalidade = modalidade
            if modalidade == 'pre':
                contrato.juros_spread = 0
                juros_mensal = parse_decimal_field('juros_mensal', percent_to_decimal=True)
                if juros_mensal is not None:
                    contrato.juros_mensal = juros_mensal
            elif modalidade == 'pos':
                contrato.juros_mensal = 0
                spread = parse_decimal_field('juros_spread', percent_to_decimal=True)
                if spread is not None:
                    contrato.juros_spread = spread
            else:
                juros_mensal = parse_decimal_field('juros_mensal', percent_to_decimal=True)
                spread = parse_decimal_field('juros_spread', percent_to_decimal=True)
                if juros_mensal is not None:
                    contrato.juros_mensal = juros_mensal
                if spread is not None:
                    contrato.juros_spread = spread
            # ... restante do código de edição ...
            contrato.erp = request.form.get('erp')
            contrato.tipo_contrato = request.form.get('tipo_juros')
            contrato.indexador = request.form.get('indexador')
            contrato.instituicao = request.form['instituicao']
            contrato.produto_id = request.form.get('produto_id')
            contrato.empresa_id = request.form.get('empresa_id')
            contrato.inicio = parse_date_or_none(request.form.get('inicio'))
            contrato.data_rescisao = parse_date_or_none(request.form.get('data_rescisao'))
            contrato.sistema_amortizacao = request.form.get('sistema_amortizacao')
            customizado_amortizacao = request.form.get('customizado_amortizacao')
            customizado_amortizacao_val = parse_customizado_amortizacao(customizado_amortizacao)
            if customizado_amortizacao and customizado_amortizacao_val is None:
                flash('Formato inválido para amortização customizada. Use uma lista de percentuais, ex: 10,20,30,40', 'danger')
                return redirect(request.url)
            if customizado_amortizacao_val is not None:
                contrato.customizado_amortizacao = customizado_amortizacao_val
            contrato.data_assinatura = parse_date_or_none(request.form.get('data_assinatura'))
            # Apenas sobrescreve se for modalidade 'pre' ou 'ambos'
            if modalidade in ['pre', 'ambos']:
                valor = parse_decimal_field('juros_mensal', percent_to_decimal=True)
                print(f"DEBUG - Juros Mensal recebido: {valor}")
                if valor is not None:
                    contrato.juros_mensal = valor

            db.session.commit()
            registrar_log('editar_contrato', f'Contrato {contrato.contrato} editado')
            flash('Contrato atualizado com sucesso!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar contrato: {str(e)}', 'danger')
    return render_template('form_contrato.html', contrato=contrato, produtos=produtos, empresas=empresas)

def calcular_parcelas(contrato):
    from decimal import Decimal, ROUND_HALF_UP
    from datetime import datetime
    from dateutil.relativedelta import relativedelta
    from sqlalchemy import desc
    import re

    def arred(val):
        try:
            d = safe_decimal(val)
            return float(d.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))
        except Exception:
            return 0.0

    def safe_int(val):
        try:
            return int(val) if val is not None else 0
        except:
            return 0

    def safe_decimal(val):
        try:
            return Decimal(str(val).replace(',', '.')) if val is not None else Decimal('0')
        except:
            return Decimal('0')

    # Corrigir: saldo_inicial deve ser apenas o valor principal do contrato
    saldo_inicial = safe_decimal(contrato.saldo_inicial)
    valor_financiado = saldo_inicial + safe_decimal(contrato.iof) + safe_decimal(contrato.tac) + safe_decimal(contrato.outros)  # Usar só para cálculo do valor da parcela, se necessário

    n = safe_int(contrato.qtd_parcela) or safe_int(contrato.prazo_meses)
    carencia_principal = safe_int(getattr(contrato, 'carencia_principal', 0))
    carencia_juros = safe_int(getattr(contrato, 'carencia_juros', 0))
    indexador = (contrato.indexador or '').upper()
    modalidade = getattr(contrato, 'modalidade', '').lower()
    sistema = getattr(contrato, 'sistema_amortizacao', 'SAC').upper()
    data_base = contrato.inicio or datetime.today().date()

    # Pega a taxa do banco central
    taxa_bcb = None
    taxa_usada_nome = taxa_usada_valor = taxa_usada_data = None
    if indexador in ['CDI', 'IPCA', 'TR', 'SELIC']:
        taxa_ref = buscar_taxa_mais_recente(indexador)
        if taxa_ref:
            taxa_bcb = safe_decimal(taxa_ref.valor) / Decimal('100')
            taxa_usada_nome = taxa_ref.nome
            taxa_usada_valor = taxa_ref.valor
            taxa_usada_data = taxa_ref.data_atualizacao

    def get_juros_mensal():
        val = getattr(contrato, 'juros_mensal', 0)
        
        # Se já é Decimal, usar diretamente
        if isinstance(val, Decimal):
            return val / Decimal('100') if val > Decimal('1') else val
        
        # Se é string, processar
        if isinstance(val, str):
            val = val.replace('%', '').replace(',', '.').strip()
            try:
                val = Decimal(val)
            except Exception:
                val = Decimal('0.0')
        else:
            # Para outros tipos (float, int), converter para Decimal preservando precisão
            val = Decimal(str(val))
        
        # Se for maior que 1, está em percentual
        return val / Decimal('100') if val > Decimal('1') else val

    def get_juros_spread():
        val = getattr(contrato, 'juros_spread', 0)
        if isinstance(val, str):
            val = val.replace('%', '').replace(',', '.').strip()
        try:
            val = Decimal(val)
        except:
            val = Decimal('0')
        return val / Decimal('100') if val > 1 else val

    # Juros mensal efetivo
    if modalidade == 'pre':
        juros_mensal = get_juros_mensal()
    elif modalidade == 'pos':
        spread = get_juros_spread()
        if taxa_bcb is not None:
            juros_mensal = (Decimal('1') + taxa_bcb + spread) ** (Decimal('1') / Decimal('12')) - Decimal('1')
        else:
            juros_mensal = spread
    else:
        juros_mensal = (
            (Decimal('1') + (taxa_bcb or Decimal('0'))) ** (Decimal('1') / Decimal('12')) - Decimal('1')
            if taxa_bcb is not None else get_juros_mensal()
        )



    # Percentuais customizados - implementação aprimorada
    customizado = sistema == 'CUSTOMIZADO' and getattr(contrato, 'customizado_amortizacao', None)
    percentuais = []
    if customizado:
        def parse_percentual(val):
            if isinstance(val, str):
                val = val.replace('%', '').replace(',', '.')
            return Decimal(val)
            
        if isinstance(customizado, list):
            if all(isinstance(p, dict) and 'percentual' in p for p in customizado):
                percentuais = [parse_percentual(p['percentual']) for p in customizado]
            elif all(isinstance(p, (float, int, str)) for p in customizado):
                percentuais = [parse_percentual(p) for p in customizado]
        elif isinstance(customizado, str):
            partes = [x.strip() for x in re.split(r'[;,	\s]+', customizado) if x.strip()]
            percentuais = [parse_percentual(p) for p in partes]
        
        # Validação dos percentuais
        if len(percentuais) != n:
            print(f'⚠️ Aviso: Número de percentuais ({len(percentuais)}) diferente do número de parcelas ({n}). '
                  f'Serão usados {min(len(percentuais), n)} percentuais.')
            percentuais = percentuais[:n]  # Ajusta para o número de parcelas
        
        # Preenche com zeros se necessário
        if len(percentuais) < n:
            percentuais.extend([Decimal('0')] * (n - len(percentuais)))
        
        # Ajusta o último percentual para garantir amortização total (com tolerância)
        soma_percentuais = sum(percentuais)
        tolerancia = Decimal('0.01')  # Tolerância de ±0.01%
        
        if abs(soma_percentuais - Decimal('100')) > tolerancia:
            print(f'⚠️ Aviso: Soma dos percentuais é {soma_percentuais}%. '
                  f'Último percentual será ajustado para completar 100%.')
            percentuais[-1] = Decimal('100') - (soma_percentuais - percentuais[-1])
        else:
            # Se está dentro da tolerância, apenas ajusta sutilmente para exatamente 100%
            if soma_percentuais != Decimal('100'):
                percentuais[-1] = percentuais[-1] + (Decimal('100') - soma_percentuais)

    n_efetivo = n - carencia_principal
    saldo_devedor = saldo_inicial  # O saldo principal do cronograma começa igual ao saldo_inicial
    parcelas = []

    def parcela_price(pv, taxa, n):
        try:
            pv = Decimal(pv)
            taxa = Decimal(taxa)
            if taxa > 0 and n > 0:
                numerador = taxa * (Decimal('1') + taxa) ** n
                denominador = (Decimal('1') + taxa) ** n - Decimal('1')
                return float(pv * numerador / denominador)
            elif n > 0:
                return float(pv / n)
            else:
                return 0.0
        except:
            return 0.0

    valor_parcela_price = Decimal('0.0')
    if sistema == 'PRICE' and n_efetivo > 0:
        valor_parcela_price = Decimal(parcela_price(saldo_inicial, juros_mensal, n_efetivo)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    valor_parcela_informada = None
    if getattr(contrato, 'parcela', None):
        valor_parcela_informada = safe_decimal(contrato.parcela)

    for i in range(1, n + 1):
        parcela = {}
        data_parcela = data_base + relativedelta(months=i - 1)
        parcela['data'] = data_parcela.strftime('%d/%m/%Y')
        parcela['status'] = 'Pendente'
        parcela['parc_paga'] = safe_int(contrato.parc_paga)
        parcela['parc_pendente'] = n - safe_int(contrato.parc_paga)

        # Salva o saldo principal ANTES de amortizar
        saldo_principal_antes = saldo_devedor
        parcela['saldo_principal'] = arred(max(saldo_principal_antes, Decimal('0')))

        # Cálculo dos juros e amortização usando saldo_principal_antes
        if sistema == 'PRICE':
            if i <= carencia_principal:
                amortizacao = Decimal('0.0')
                juros = saldo_principal_antes * juros_mensal if i > carencia_juros else Decimal('0.0')
                valor_parcela = juros
            else:
                juros = saldo_principal_antes * juros_mensal if i > carencia_juros else Decimal('0.0')
                if valor_parcela_informada is not None:
                    valor_parcela = valor_parcela_informada
                else:
                    valor_parcela = valor_parcela_price
                amortizacao = valor_parcela - juros
        elif sistema == 'SAC':
            if valor_parcela_informada is not None and i > carencia_principal:
                valor_parcela = valor_parcela_informada
                juros = saldo_principal_antes * juros_mensal if i > carencia_juros else Decimal('0.0')
                amortizacao = valor_parcela - juros
            else:
                amortizacao = saldo_inicial / Decimal(n_efetivo) if i > carencia_principal else Decimal('0.0')
                juros = saldo_principal_antes * juros_mensal if i > carencia_juros else Decimal('0.0')
                valor_parcela = amortizacao + juros
        elif sistema == 'BULLET':
            amortizacao = saldo_inicial if i == n else Decimal('0.0')
            juros = saldo_principal_antes * juros_mensal if i > carencia_juros else Decimal('0.0')
            valor_parcela = juros + amortizacao if i == n else juros
        elif sistema == 'CUSTOMIZADO' and percentuais:
            percentual = percentuais[i-1] / Decimal('100')
            juros = saldo_principal_antes * juros_mensal if i > carencia_juros else Decimal('0.0')
            if i == n:
                amortizacao = saldo_principal_antes
            else:
                amortizacao = saldo_inicial * percentual if i > carencia_principal else Decimal('0.0')
            valor_parcela = juros + amortizacao
        else:
            amortizacao = Decimal('0.0')
            juros = Decimal('0.0')
            valor_parcela = Decimal('0.0')

        # Subtrai a amortização do saldo devedor APÓS salvar o saldo principal
        saldo_devedor -= amortizacao
        if i == n:
            saldo_devedor = Decimal('0.0')

        if modalidade == 'pos' and taxa_bcb is not None:
            taxa_efetiva = (Decimal('1') + taxa_bcb + get_juros_spread()) ** (Decimal('1') / Decimal('12')) - Decimal('1')
            parcela['juros_percentual'] = format_taxa_percentual(taxa_efetiva)
        else:
            parcela['juros_percentual'] = format_taxa_percentual(juros_mensal)

        parcela['numero'] = i
        parcela['juros_pago'] = arred(juros)
        parcela['amortizacao'] = arred(amortizacao)
        parcela['pgto_juros'] = arred(juros)
        parcela['valor_parcela'] = arred(valor_parcela)
        parcela['saldo_juros'] = 0.0
        parcela['saldo_total_acum'] = arred(max(saldo_devedor, Decimal('0')) + Decimal('0.0'))
        if sistema == 'CUSTOMIZADO' and percentuais:
            parcela['percentual_amortizacao'] = f"{percentuais[i-1]}%"
        parcelas.append(parcela)

    return {
        'parcelas': parcelas,
        'taxa_usada_nome': taxa_usada_nome,
        'taxa_usada_valor': taxa_usada_valor,
        'taxa_usada_data': taxa_usada_data,
        'saldo_final': arred(saldo_devedor)  # Deve ser zero no final
    }

@app.route('/contrato/<int:id>/detalhes')
@login_required
def detalhes_contrato(id):
    # Adicionar parâmetro de cache-busting para forçar atualização
    cache_bust = request.args.get('cb', '')
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    contrato = Contrato.query.get_or_404(id)
    resultado = calcular_parcelas(contrato)
    parcelas = resultado['parcelas']
    taxa_usada_nome = resultado['taxa_usada_nome']
    taxa_usada_valor = resultado['taxa_usada_valor']
    taxa_usada_data = resultado['taxa_usada_data']

    # Calcular valores agregados
    principal_pago = sum(p['amortizacao'] for i, p in enumerate(parcelas[:contrato.parc_paga or 0])) if parcelas else 0
    principal_pendente = sum(p['amortizacao'] for i, p in enumerate(parcelas[contrato.parc_paga or 0:])) if parcelas else float(contrato.saldo_inicial or 0)
    juros_pago = sum(p['pgto_juros'] for i, p in enumerate(parcelas[:contrato.parc_paga or 0])) if parcelas else 0
    juros_pendente = sum(p['pgto_juros'] for i, p in enumerate(parcelas[contrato.parc_paga or 0:])) if parcelas else 0
    saldo_devedor = principal_pendente + juros_pendente

    # Calcular data de fim
    data_fim_calculada = None
    if contrato.inicio and contrato.qtd_parcela:
        try:
            data_fim_calculada = contrato.inicio + relativedelta(months=contrato.qtd_parcela)
        except Exception:
            data_fim_calculada = None

    valor_parcela_calculado = parcelas[0]['valor_parcela'] if parcelas else None

    # Calcular TIR real (removido pyxirr)
    tir_real = None
    # Para calcular a TIR real, instale a biblioteca pyxirr e implemente aqui se necessário.

    return render_template('detalhes_contrato.html', contrato=contrato, parcelas=parcelas, data_fim_calculada=data_fim_calculada, valor_parcela_calculado=valor_parcela_calculado, principal_pago=principal_pago, principal_pendente=principal_pendente, juros_pago=juros_pago, juros_pendente=juros_pendente, saldo_devedor=saldo_devedor, tir_real=tir_real, taxa_usada_nome=taxa_usada_nome, taxa_usada_valor=taxa_usada_valor, taxa_usada_data=taxa_usada_data, cache_bust=cache_bust)

@app.route('/contrato/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_contrato(id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    contrato = Contrato.query.get_or_404(id)
    try:
        db.session.delete(contrato)
        db.session.commit()
        registrar_log('excluir_contrato', f'Contrato {contrato.contrato} excluído')
        flash('Contrato excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir contrato: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/sobre', methods=['GET', 'POST'])
@login_required
def sobre():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        secret_key = request.form.get('secret_key')
        with open('.env', 'a') as f:
            f.write(f'SECRET_KEY={secret_key}\n')
        flash('Configurações salvas com sucesso!', 'success')
        return redirect(url_for('sobre'))
    return render_template('sobre.html')

@app.route('/relatorios')
@login_required
def relatorios():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    # Filtros
    query = Contrato.query
    instituicao = request.args.get('instituicao')
    if instituicao and instituicao.strip() not in ('', 'todas', 'Todos'):
        query = query.filter(Contrato.instituicao.ilike(f"%{instituicao.strip()}%"))
    produto = request.args.get('produto')
    if produto and produto not in ('', 'todos', 'Todos'):
        query = query.filter(Contrato.produto == produto)
    modalidade = request.args.get('modalidade')
    if modalidade and modalidade not in ('', 'todas', 'Todas'):
        query = query.filter(Contrato.modalidade == modalidade)
    status = request.args.get('status')
    if status == 'ativos':
        query = query.filter(Contrato.parc_pendente > 0)
    elif status == 'quitados':
        query = query.filter(Contrato.parc_pendente == 0)
    numero_contrato = request.args.get('numero_contrato')
    if numero_contrato and numero_contrato.strip() != '':
        query = query.filter(Contrato.contrato.contains(numero_contrato))
    ano = request.args.get('ano')
    if ano and ano.strip() != '':
        try:
            query = query.filter(db.extract('year', Contrato.inicio) == int(ano))
        except ValueError:
            pass
    mes = request.args.get('mes')
    if mes and mes.strip() != '':
        try:
            query = query.filter(db.extract('month', Contrato.inicio) == int(mes))
        except ValueError:
            pass
    contratos = query.options(joinedload(Contrato.empresa)).outerjoin(Empresa).order_by(Empresa.nome, Contrato.inicio).all()

    # Gráfico por instituição
    instituicoes = {}
    for c in contratos:
        key = c.empresa.nome or 'Não informado'
        instituicoes.setdefault(key, 0)
        instituicoes[key] += float(c.saldo_inicial or 0)
    instituicao_labels = list(instituicoes.keys())
    instituicao_data = list(instituicoes.values())

    # Gráfico por indexador
    indexadores = {}
    for c in contratos:
        key = c.indexador or 'Não informado'
        indexadores.setdefault(key, 0)
        indexadores[key] += float(c.saldo_inicial or 0)
    indexador_labels = list(indexadores.keys())
    indexador_data = list(indexadores.values())

    # Tabela de bancos
    bancos_dict = {}
    total_geral = 0
    for c in contratos:
        nome = c.empresa.nome or 'Não informado'
        if nome not in bancos_dict:
            bancos_dict[nome] = {
                'nome': nome,
                'montante': 0,
                'cp': 0,
                'lp': 0,
                'ativos': 0,
                'liquidados': 0
            }
        bancos_dict[nome]['montante'] += float(c.saldo_inicial or 0)
        bancos_dict[nome]['cp'] += float(c.curto_pz or 0)
        bancos_dict[nome]['lp'] += float(c.longo_pz or 0)
        if c.parc_pendente == 0:
            bancos_dict[nome]['liquidados'] += 1
        else:
            bancos_dict[nome]['ativos'] += 1
        total_geral += float(c.saldo_inicial or 0)
    bancos = []
    for b in bancos_dict.values():
        b['percentual'] = round((b['montante']/total_geral)*100, 2) if total_geral else 0
        b['percentual_cp'] = round((b['cp']/b['montante'])*100, 2) if b['montante'] else 0
        b['percentual_lp'] = round((b['lp']/b['montante'])*100, 2) if b['montante'] else 0
        bancos.append(b)

    contratos_lista = []
    for c in contratos:
        # Data de fim
        try:
            if c.inicio and c.qtd_parcela:
                data_fim_calculada = c.inicio + relativedelta(months=c.qtd_parcela)
            else:
                data_fim_calculada = None
        except Exception:
            data_fim_calculada = None
        # Juros pendentes
        try:
            resultado = calcular_parcelas(c)
            parcelas = resultado['parcelas']
            juros_pendente = sum(p['pgto_juros'] for i, p in enumerate(parcelas[c.parc_paga or 0:])) if parcelas else 0
        except Exception:
            juros_pendente = 0
        c.data_fim_calculada = data_fim_calculada
        c.juros_pendente_calculado = juros_pendente
        # Corrigir empresa para nome
        c.empresa_nome = c.empresa.nome if c.empresa else ''
        contratos_lista.append(c)

    return render_template('relatorios.html', contratos=contratos_lista,
        instituicao_labels=instituicao_labels, instituicao_data=instituicao_data,
        indexador_labels=indexador_labels, indexador_data=indexador_data,
        bancos=bancos)

@app.route('/bancos_bcb')
def bancos_bcb():
    import csv
    import requests
    url = 'https://www.bcb.gov.br/content/estabilidadefinanceira/str1/ParticipantesSTR.csv'
    response = requests.get(url)
    response.encoding = 'utf-8'
    bancos = []
    if response.status_code == 200:
        reader = csv.DictReader(response.text.splitlines(), delimiter=',')
        for row in reader:
            codigo = row.get('N\u00famero_C\u00f3digo')
            nome = row.get('Nome_Reduzido')
            if codigo and nome and codigo.isdigit():
                bancos.append({
                    'codigo': codigo.strip(),
                    'nome': nome.strip()
                })
    return jsonify(bancos)

@app.route('/exportar_contratos')
@login_required
def exportar_contratos():
    query = Contrato.query
    instituicao = request.args.get('instituicao')
    if instituicao and instituicao.strip() not in ('', 'todas', 'Todos'):
        query = query.filter(Contrato.instituicao.ilike(f"%{instituicao.strip()}%"))
    produto = request.args.get('produto')
    if produto and produto not in ('', 'todos', 'Todos'):
        query = query.filter(Contrato.produto == produto)
    modalidade = request.args.get('modalidade')
    if modalidade and modalidade not in ('', 'todas', 'Todas'):
        query = query.filter(Contrato.modalidade == modalidade)
    status = request.args.get('status')
    if status == 'ativos':
        query = query.filter(Contrato.parc_pendente > 0)
    elif status == 'quitados':
        query = query.filter(Contrato.parc_pendente == 0)
    numero_contrato = request.args.get('numero_contrato')
    if numero_contrato and numero_contrato.strip() != '':
        query = query.filter(Contrato.contrato.contains(numero_contrato))
    ano = request.args.get('ano')
    if ano and ano.strip() != '':
        try:
            query = query.filter(db.extract('year', Contrato.inicio) == int(ano))
        except ValueError:
            pass
    mes = request.args.get('mes')
    if mes and mes.strip() != '':
        try:
            query = query.filter(db.extract('month', Contrato.inicio) == int(mes))
        except ValueError:
            pass
    contratos = query.outerjoin(Empresa).order_by(Empresa.nome, Contrato.inicio).all()
    def to_brl(val):
        return f'R$ {val:,.2f}'.replace(',', 'X').replace('.', ',').replace('X', '.') if val is not None else ''
    def safe_str(val):
        return str(val) if val is not None else ''
    output = []
    header = ['Contrato', 'Empresa', 'Instituição', 'Saldo Inicial', 'Saldo Devedor', 'Indexador', 'Juros Mensal', 'Modalidade', 'ERP', 'Parcelas Pagas', 'Parcelas Pendentes', 'Status']
    output.append(header)
    for c in contratos:
        status = 'Quitado' if c.parc_pendente == 0 else ('Novo' if c.parc_pendente == c.qtd_parcela else 'Em andamento')
        output.append([
            c.contrato,
            c.empresa.nome,
            c.instituicao,
            to_brl(c.saldo_inicial),
            to_brl(c.saldo_devedor),
            c.indexador,
            f'{c.juros_mensal:.4f}%' if c.juros_mensal is not None else '',
            c.modalidade,
            c.erp,
            c.parc_paga,
            c.parc_pendente,
            status
        ])
    def generate():
        for row in output:
            yield ';'.join([safe_str(col) for col in row]) + '\n'
    return Response(generate(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=contratos_filtrados.csv"})

@app.route('/exportar_relatorios')
@login_required
def exportar_relatorios():
    query = Contrato.query
    instituicao = request.args.get('instituicao')
    if instituicao and instituicao.strip() not in ('', 'todas', 'Todos'):
        query = query.filter(Contrato.instituicao.ilike(f"%{instituicao.strip()}%"))
    produto = request.args.get('produto')
    if produto and produto not in ('', 'todos', 'Todos'):
        query = query.filter(Contrato.produto == produto)
    modalidade = request.args.get('modalidade')
    if modalidade and modalidade not in ('', 'todas', 'Todas'):
        query = query.filter(Contrato.modalidade == modalidade)
    status = request.args.get('status')
    if status == 'ativos':
        query = query.filter(Contrato.parc_pendente > 0)
    elif status == 'quitados':
        query = query.filter(Contrato.parc_pendente == 0)
    numero_contrato = request.args.get('numero_contrato')
    if numero_contrato and numero_contrato.strip() != '':
        query = query.filter(Contrato.contrato.contains(numero_contrato))
    ano = request.args.get('ano')
    if ano and ano.strip() != '':
        try:
            query = query.filter(db.extract('year', Contrato.inicio) == int(ano))
        except ValueError:
            pass
    mes = request.args.get('mes')
    if mes and mes.strip() != '':
        try:
            query = query.filter(db.extract('month', Contrato.inicio) == int(mes))
        except ValueError:
            pass
    contratos = query.outerjoin(Empresa).order_by(Empresa.nome, Contrato.inicio).all()
    def to_brl(val):
        return f'R$ {val:,.2f}'.replace(',', 'X').replace('.', ',').replace('X', '.') if val is not None else ''
    def safe_str(val):
        return str(val) if val is not None else ''
    output = []
    header = ['Contrato', 'Empresa', 'Instituição', 'Saldo Inicial', 'Principal Pend.', 'Juros Pend.', 'Total Pend.', 'Data de Fim']
    output.append(header)
    for c in contratos:
        # Data de fim calculada
        try:
            if c.inicio and c.qtd_parcela:
                data_fim_calculada = c.inicio + relativedelta(months=c.qtd_parcela)
            else:
                data_fim_calculada = None
        except Exception:
            data_fim_calculada = None
        # Juros pendente calculado
        try:
            resultado = calcular_parcelas(c)
            parcelas = resultado['parcelas']
            juros_pendente = sum(p['pgto_juros'] for i, p in enumerate(parcelas[c.parc_paga or 0:])) if parcelas else 0
        except Exception:
            juros_pendente = 0
        principal_pendente = c.principal_pendente if c.principal_pendente is not None else ''
        total_pendente = (float(principal_pendente or 0) + float(juros_pendente or 0)) if principal_pendente != '' and juros_pendente != '' else ''
        data_fim = data_fim_calculada.strftime('%d/%m/%Y') if data_fim_calculada else ''
        output.append([
            c.contrato,
            c.empresa.nome,
            c.instituicao,
            to_brl(c.saldo_inicial),
            to_brl(principal_pendente),
            to_brl(juros_pendente),
            to_brl(total_pendente),
            data_fim
        ])
    def generate():
        for row in output:
            yield ';'.join([safe_str(col) for col in row]) + '\n'
    return Response(generate(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=relatorio_contratos_filtrados.csv"})

@app.route('/logs')
@login_required
def logs():
    if not current_user.is_admin:
        flash('Acesso restrito ao administrador.', 'danger')
        return redirect(url_for('index'))
    query = LogSistema.query
    usuario = request.args.get('usuario')
    if usuario:
        query = query.filter(LogSistema.usuario.ilike(f"%{usuario}%"))
    acao = request.args.get('acao')
    if acao:
        query = query.filter(LogSistema.acao.ilike(f"%{acao}%"))
    logs = query.order_by(LogSistema.data_hora.desc()).limit(500).all()
    return render_template('logs.html', logs=logs)

@app.route('/taxa_indexador/<indexador>')
@login_required
def taxa_indexador(indexador):
    taxa_ref = TaxaReferencia.query.filter(TaxaReferencia.nome.ilike(f"%{indexador}%")).order_by(desc(TaxaReferencia.data_atualizacao)).first()
    if taxa_ref:
        return jsonify({"taxa": taxa_ref.valor})
    return jsonify({"taxa": None}), 404

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('login'))

# Before request - check if user is authenticated for all routes except login and static files
@app.before_request
def before_request():
    # List of endpoints that don't require authentication
    allowed_endpoints = ['login', 'static']
    
    if not current_user.is_authenticated and request.endpoint not in allowed_endpoints:
        return redirect(url_for('login', next=request.url))
    
    if current_user.is_authenticated:
        registrar_log('acesso', f'Acesso à rota: {request.endpoint}')
    
import requests

# ------------------ FUNÇÕES AUXILIARES ------------------

from datetime import datetime
import pytz

def get_horario_brasilia():
    fuso_brasilia = pytz.timezone('America/Sao_Paulo')
    return datetime.now(fuso_brasilia)


def get_taxa_bcb(codigo_serie):
    url = f"https://api.bcb.gov.br/dados/serie/bcdata.sgs.{codigo_serie}/dados/ultimos/1?formato=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        dados = response.json()
        if dados:
            return dados[0]['valor']
        else:
            return None
    except Exception as e:
        print(f"Erro ao buscar série {codigo_serie}: {e}")
        return None

def get_cdi_anual_b3():
    from datetime import datetime
    ano_atual = datetime.now().year
    urls = [
        f'https://www2.b3.com.br/pt_br/market-data-e-indices/indices/indices-de-renda-fixa/cdi/series-historicas/SeriesHistoricas_{ano_atual}.csv',
        f'https://www2.b3.com.br/pt_br/market-data-e-indices/indices/indices-de-renda-fixa/cdi/series-historicas/SeriesHistoricas_{ano_atual-1}.csv'
    ]
    for url in urls:
        try:
            response = requests.get(url, timeout=15)
            print(f"Tentando baixar: {url} - Status: {response.status_code}")
            if response.status_code != 200:
                continue
            response.encoding = 'utf-8'
            lines = response.text.splitlines()
            print("Primeiras linhas do CSV:")
            for l in lines[:5]:
                print(l)
            for line in reversed(lines):
                parts = line.split(';')
                if len(parts) >= 2:
                    data, valor = parts[0].strip(), parts[1].strip().replace(',', '.')
                    try:
                        valor_float = float(valor)
                        if valor_float > 0:
                            return data, valor_float
                    except:
                        continue
            return None, None
        except Exception as e:
            print(f'Erro ao buscar CDI anual B3 ({url}): {e}')
            continue
    return None, None

def get_cdi_anual_b3_html():
    url = 'https://www.b3.com.br/pt_br/market-data-e-indices/servicos-de-dados/market-data/consultas/mercado-de-derivativos/precos-referenciais/taxas-referenciais-bm-fbovespa/'
    try:
        response = requests.get(url, timeout=15)
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'html.parser')
        # Procurar por linhas que contenham "CDI" e valor percentual
        for row in soup.find_all(['tr', 'div']):
            text = row.get_text(separator=' ', strip=True)
            if 'CDI' in text and '%' in text:
                import re
                match = re.search(r'([\d\.,]+)\s*%', text)
                if match:
                    valor = match.group(1).replace('.', '').replace(',', '.')
                    try:
                        valor_float = float(valor)
                        if valor_float > 0:
                            return valor_float
                    except:
                        continue
        return None
    except Exception as e:
        print(f'Erro ao buscar CDI anual B3 HTML: {e}')
        return None

def atualizar_taxas():
    taxas_para_atualizar = {
        "SELIC Meta": 432,
        "SELIC Efetiva": 4189,
        "CDI": 12,
        "IPCA": 433,
        "TR": 226,
    }

    for nome, codigo in taxas_para_atualizar.items():
        valor = get_taxa_bcb(codigo)
        if valor:
            nova_taxa = TaxaReferencia(
                nome=nome,
                valor=valor,
                data_atualizacao=get_horario_brasilia()
            )
            db.session.add(nova_taxa)

    # Adiciona o Dólar
    dolar = get_dolar_comercial()
    if dolar:
        nova_taxa = TaxaReferencia(
            nome="Dólar Comercial",
            valor=dolar,
            data_atualizacao=get_horario_brasilia()
        )
        db.session.add(nova_taxa)

    # Adiciona CDI anual B3 HTML
    valor_cdi_html = get_cdi_anual_b3_html()
    if valor_cdi_html:
        nova_taxa = TaxaReferencia(
            nome=f"CDI Anual (B3)",
            valor=valor_cdi_html,
            data_atualizacao=get_horario_brasilia()
        )
        db.session.add(nova_taxa)

    db.session.commit()
    print("✅ Taxas atualizadas com sucesso!")
    
def get_dolar_comercial():
    url = "https://economia.awesomeapi.com.br/json/last/USD-BRL"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        return data['USDBRL']['bid']  # Valor de compra
    except Exception as e:
        print(f"Erro ao buscar Dólar: {e}")
        return None
    

from sqlalchemy import desc
from apscheduler.schedulers.background import BackgroundScheduler


@app.route('/taxas')
def painel_taxas():
    nomes_taxas = ["SELIC Meta", "SELIC Efetiva", "CDI", "IPCA", "TR"]
    taxas_atual = {}

    for nome in nomes_taxas:
        ultima_taxa = TaxaReferencia.query.filter_by(nome=nome).order_by(desc(TaxaReferencia.data_atualizacao)).first()
        if ultima_taxa:
            taxas_atual[nome] = f"{ultima_taxa.valor} (Atualizado em {ultima_taxa.data_atualizacao.strftime('%d/%m/%Y')})"
        else:
            taxas_atual[nome] = "Sem dados"

    # Buscar todas as últimas taxas CETIP/B3 distintas
    subq = db.session.query(
        TaxaReferencia.nome,
        func.max(TaxaReferencia.data_atualizacao).label('max_data')
    ).filter(TaxaReferencia.nome != None).group_by(TaxaReferencia.nome).subquery()
    taxas_cetip_lista = db.session.query(TaxaReferencia).join(
        subq,
        (TaxaReferencia.nome == subq.c.nome) & (TaxaReferencia.data_atualizacao == subq.c.max_data)
    ).filter(
        (TaxaReferencia.nome.ilike('%CETIP%')) |
        (TaxaReferencia.nome.ilike('%CDI%')) |
        (TaxaReferencia.nome.ilike('%B3%'))
    ).order_by(TaxaReferencia.nome).all()

    # Buscar CDI anual CETIP/B3 mais recente
    cdi_cetip = db.session.query(TaxaReferencia).filter(
        TaxaReferencia.nome.ilike('%CDI%'),
        TaxaReferencia.nome.ilike('%a.a.%')
    ).order_by(desc(TaxaReferencia.data_atualizacao)).first()

    return render_template('taxas.html', taxas=taxas_atual, taxas_cetip_lista=taxas_cetip_lista, cdi_cetip=cdi_cetip)

@app.route('/historico_taxas')
def historico_taxas():
    todas_taxas = TaxaReferencia.query.order_by(desc(TaxaReferencia.data_atualizacao)).limit(100).all()
    return render_template('historico_taxas.html', taxas=todas_taxas)

@app.route('/atualizar_taxas')
def atualizar_taxas_manual():
    atualizar_taxas()
    return redirect(url_for('painel_taxas'))




# ------------------ SCHEDULER AUTOMÁTICO ------------------

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=atualizar_taxas, trigger="cron", hour=9, minute=0)  # Atualização BCB
    scheduler.add_job(func=buscar_taxas_cetip, trigger="cron", hour=9, minute=30)  # CETIP
    scheduler.start()
    print("✅ Scheduler iniciado: Atualização diária às 09:00 (BCB) e 09:30 (CETIP)")

# Mover a função buscar_taxas_cetip para antes de start_scheduler
def buscar_taxas_cetip():
    url = 'http://estatisticas.cetip.com.br/astec/series_v05/paginas/lum_web_v04_10_03_consulta.asp'
    try:
        response = requests.get(url, timeout=15)
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'html.parser')
        taxas = {}
        for row in soup.find_all('tr'):
            if not isinstance(row, Tag):
                continue
            cols = row.find_all('td')
            if len(cols) >= 2:
                nome = cols[0].get_text(strip=True)
                valor = cols[1].get_text(strip=True)
                if nome and valor:
                    taxas[nome] = valor
        for nome, valor in taxas.items():
            nova_taxa = TaxaReferencia(
                nome=nome,
                valor=valor,
                data_atualizacao=get_horario_brasilia()
            )
            db.session.add(nova_taxa)
        db.session.commit()
        print('✅ Taxas CETIP atualizadas com sucesso!')
        return taxas
    except Exception as e:
        print(f'Erro ao buscar taxas CETIP: {e}')
        return None

start_scheduler()

@app.template_filter('brl')
def format_brl(value):
    try:
        return 'R$ {:,.2f}'.format(float(value)).replace(',', 'X').replace('.', ',').replace('X', '.')
    except:
        return value

def registrar_log(acao, detalhes=None):
    from flask import request
    if current_user.is_authenticated:
        usuario = current_user.username
    else:
        usuario = 'desconhecido'
    ip = request.remote_addr
    fuso_brasilia = pytz.timezone('America/Sao_Paulo')
    data_hora = datetime.now(fuso_brasilia)
    log = LogSistema(usuario=usuario, acao=acao, detalhes=detalhes, ip=ip, data_hora=data_hora)
    db.session.add(log)
    db.session.commit()

ALLOWED_EXTENSIONS = {'xlsx', 'csv'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/importar_contratos', methods=['GET', 'POST'])
@login_required
def importar_contratos():
    if not current_user.is_admin:
        flash('Acesso restrito ao administrador.', 'danger')
        return redirect(url_for('index'))
    contratos_importados = []
    erros = []
    if request.method == 'POST':
        file = request.files.get('arquivo')
        if not file or file.filename == '':
            flash('Selecione um arquivo para importar.', 'warning')
            return render_template('importar_contratos.html', contratos_importados=contratos_importados, erros=erros)
        if not allowed_file(file.filename):
            flash('Formato de arquivo não suportado. Use .xlsx ou .csv', 'danger')
            return render_template('importar_contratos.html', contratos_importados=contratos_importados, erros=erros)
        filename = secure_filename(file.filename or '')
        try:
            if filename.endswith('.csv'):
                df = pd.read_csv(file.stream)
            else:
                df = pd.read_excel(file.stream)
            for idx, row in df.iterrows():
                try:
                    contrato = Contrato(
                        contrato=str(row.get('contrato', '')).strip(),
                        empresa_id=row.get('empresa_id'),
                        produto_id=row.get('produto_id'),
                        instituicao=str(row.get('instituicao', '')).strip(),
                        inicio=pd.to_datetime(str(row.get('inicio', '') or ''), errors='coerce').date() if row.get('inicio', None) else None,
                        saldo_inicial=row.get('saldo_inicial', 0) or 0,
                        indexador=str(row.get('indexador', '')).strip(),
                        juros_mensal=row.get('juros_mensal', None),
                        qtd_parcela=int(row.get('qtd_parcela', 0) or 0),
                        parc_paga=int(row.get('parc_paga', 0) or 0),
                        parc_pendente=int(row.get('parc_pendente', 0) or 0),
                        erp=str(row.get('erp', '')).strip(),
                        modalidade=str(row.get('modalidade', '')).strip(),
                        sistema_amortizacao=str(row.get('sistema_amortizacao', '')).strip(),
                        iof=row.get('iof', 0) or 0,
                        tac=row.get('tac', 0) or 0,
                        outros=row.get('outros', 0) or 0
                    )
                    db.session.add(contrato)
                    contratos_importados.append(contrato)
                except Exception as e:
                    linha = str(idx)
                    erros.append(f"Linha {linha}: {str(e)}")
            db.session.commit()
            flash(f'{len(contratos_importados)} contratos importados com sucesso.', 'success')
        except Exception as e:
            erros.append(str(e))
            flash('Erro ao importar arquivo.', 'danger')
    return render_template('importar_contratos.html', contratos_importados=contratos_importados, erros=erros)

@app.route('/importar_contratos_api', methods=['GET', 'POST'])
@login_required
def importar_contratos_api():
    if not current_user.is_admin:
        flash('Acesso restrito ao administrador.', 'danger')
        return redirect(url_for('index'))
    contratos_importados = []
    erros = []
    if request.method == 'POST':
        url_api = request.form.get('url_api') or ''
        token = request.form.get('token') or ''
        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        if not url_api.strip():
            erros.append('Informe a URL da API.')
        else:
            try:
                response = requests.get(url_api, headers=headers, timeout=20)
                if response.status_code == 200:
                    data = response.json()
                    for idx, row in enumerate(data):
                        try:
                            contrato = Contrato(
                                contrato=str(row.get('contrato', '')).strip(),
                                empresa_id=row.get('empresa_id'),
                                produto_id=row.get('produto_id'),
                                instituicao=str(row.get('instituicao', '')).strip(),
                                inicio=pd.to_datetime(row.get('inicio', None), errors='coerce').date() if row.get('inicio', None) else None,
                                saldo_inicial=row.get('saldo_inicial', 0) or 0,
                                indexador=str(row.get('indexador', '')).strip(),
                                juros_mensal=row.get('juros_mensal', None),
                                qtd_parcela=int(row.get('qtd_parcela', 0) or 0),
                                parc_paga=int(row.get('parc_paga', 0) or 0),
                                parc_pendente=int(row.get('parc_pendente', 0) or 0),
                                erp=str(row.get('erp', '')).strip(),
                                modalidade=str(row.get('modalidade', '')).strip(),
                                sistema_amortizacao=str(row.get('sistema_amortizacao', '')).strip(),
                                iof=row.get('iof', 0) or 0,
                                tac=row.get('tac', 0) or 0,
                                outros=row.get('outros', 0) or 0
                            )
                            db.session.add(contrato)
                            contratos_importados.append(contrato)
                        except Exception as e:
                            linha = str(idx)
                            erros.append(f"Contrato {linha}: {str(e)}")
                    db.session.commit()
                    flash(f'{len(contratos_importados)} contratos importados da API.', 'success')
                else:
                    erros.append(f'Erro na requisição: {response.status_code} - {response.text}')
            except Exception as e:
                erros.append(str(e))
                flash('Erro ao importar da API.', 'danger')
    return render_template('importar_contratos_api.html', contratos_importados=contratos_importados, erros=erros)

def resposta_simples_ia(pergunta, contratos):
    pergunta = pergunta.lower()
    if any(p in pergunta for p in ["olá", "oi", "bom dia", "boa tarde", "boa noite"]):
        return "Olá! Como posso ajudar você sobre os contratos?"
    if "ajuda" in pergunta:
        return "Você pode perguntar sobre contratos ativos, quitados, saldo devedor, empresas, instituições, detalhes de contratos e mais!"
    if "contratos" in pergunta and ("como estão" in pergunta or "resumo" in pergunta):
        total = len(contratos)
        ativos = sum(1 for c in contratos if c.parc_pendente and c.parc_pendente > 0)
        quitados = total - ativos
        return f"Você possui {total} contratos cadastrados, sendo {ativos} ativos e {quitados} quitados."
    if "contratos ativos" in pergunta:
        ativos = [c for c in contratos if c.parc_pendente and c.parc_pendente > 0]
        if not ativos:
            return "Não há contratos ativos no momento."
        lista = '\n'.join([f"Contrato: {c.contrato}, Empresa: {c.empresa.nome}, Instituição: {c.instituicao}, Saldo Devedor: R$ {c.saldo_devedor}" for c in ativos])
        return f"Contratos ativos:\n{lista}"
    if "contratos quitados" in pergunta:
        quitados = [c for c in contratos if not c.parc_pendente or c.parc_pendente == 0]
        if not quitados:
            return "Não há contratos quitados no momento."
        lista = '\n'.join([f"Contrato: {c.contrato}, Empresa: {c.empresa.nome}, Instituição: {c.instituicao}" for c in quitados])
        return f"Contratos quitados:\n{lista}"
    if "informações dos contratos" in pergunta or "informacoes dos contratos" in pergunta:
        total = len(contratos)
        empresas = set(c.empresa.nome for c in contratos)
        instituicoes = set(c.instituicao for c in contratos)
        return f"Total de contratos: {total}\nEmpresas: {', '.join(empresas)}\nInstituições: {', '.join(instituicoes)}"
    if "saldo devedor" in pergunta:
        saldo_total = sum(float(getattr(c, 'saldo_devedor_calculado', c.saldo_devedor) or 0) for c in contratos)
        return f"O saldo devedor total dos contratos é R$ {saldo_total:,.2f}."
    if "empresas" in pergunta:
        empresas = set(c.empresa.nome for c in contratos)
        return f"Empresas com contratos cadastrados: {', '.join(empresas)}"
    if "instituições" in pergunta or "instituicoes" in pergunta:
        instituicoes = set(c.instituicao for c in contratos)
        return f"Instituições com contratos cadastrados: {', '.join(instituicoes)}"
    if "contratos da empresa" in pergunta:
        for c in contratos:
            if c.empresa.nome.lower() in pergunta:
                return f"Contrato: {c.contrato}, Instituição: {c.instituicao}, Saldo Devedor: R$ {c.saldo_devedor}"
        return "Não encontrei contratos para essa empresa."
    if "contratos da instituição" in pergunta or "contratos da instituicao" in pergunta:
        for c in contratos:
            if c.instituicao.lower() in pergunta:
                return f"Contrato: {c.contrato}, Empresa: {c.empresa.nome}, Saldo Devedor: R$ {c.saldo_devedor}"
        return "Não encontrei contratos para essa instituição."
    if "detalhes do contrato" in pergunta:
        for c in contratos:
            if c.contrato.lower() in pergunta:
                return f"Contrato: {c.contrato}\nEmpresa: {c.empresa.nome}\nInstituição: {c.instituicao}\nSaldo Devedor: R$ {c.saldo_devedor}\nStatus: {'Ativo' if c.parc_pendente and c.parc_pendente > 0 else 'Quitado'}"
        return "Não encontrei esse contrato."
    if "relatório" in pergunta or "relatorio" in pergunta:
        total = len(contratos)
        ativos = sum(1 for c in contratos if c.parc_pendente and c.parc_pendente > 0)
        quitados = total - ativos
        saldo_total = sum(float(getattr(c, 'saldo_devedor_calculado', c.saldo_devedor) or 0) for c in contratos)
        return f"Relatório resumido:\nTotal de contratos: {total}\nAtivos: {ativos}\nQuitados: {quitados}\nSaldo devedor total: R$ {saldo_total:,.2f}"
    return "Desculpe, não entendi sua pergunta. Você pode perguntar sobre contratos ativos, quitados, saldo devedor, empresas, instituições, detalhes de contratos, etc."

@app.route('/assistente_ia', methods=['GET', 'POST'])
@login_required
def assistente_ia():
    if request.method == 'GET':
        return render_template('assistente.html')
    data = request.get_json()
    pergunta = data.get('pergunta', '').strip()
    contratos = Contrato.query.all()
    resposta = resposta_simples_ia(pergunta, contratos)
    return jsonify({'resposta': resposta})

@app.route('/empresas')
@login_required
def listar_empresas():
    empresas = Empresa.query.order_by(Empresa.nome).all()
    return render_template('empresas.html', empresas=empresas)

@app.route('/cadastrar-empresa', methods=['GET', 'POST'])
@login_required
def cadastrar_empresa():
    if request.method == 'POST':
        nome = request.form.get('nome')
        if not nome:
            flash('Nome da empresa é obrigatório.', 'danger')
            return redirect(url_for('cadastrar_empresa'))
        if Empresa.query.filter_by(nome=nome).first():
            flash('Empresa já cadastrada.', 'danger')
            return redirect(url_for('cadastrar_empresa'))
        empresa = Empresa(nome=nome)
        db.session.add(empresa)
        db.session.commit()
        flash('Empresa cadastrada com sucesso!', 'success')
        return redirect(url_for('listar_empresas'))
    return render_template('cadastro_empresa.html')

@app.route('/empresa/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_empresa(id):
    empresa = Empresa.query.get_or_404(id)
    try:
        db.session.delete(empresa)
        db.session.commit()
        flash('Empresa excluída com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir empresa: {str(e)}', 'danger')
    return redirect(url_for('listar_empresas'))

@app.route('/debug_taxas')
def debug_taxas():
    taxas = TaxaReferencia.query.order_by(desc(TaxaReferencia.data_atualizacao)).limit(30).all()
    html = '<h2>Taxas Recentes</h2><ul>'
    for t in taxas:
        html += f'<li><b>{t.nome}</b>: {t.valor} (Atualizado em {t.data_atualizacao.strftime("%d/%m/%Y %H:%M")})</li>'
    html += '</ul>'
    return html

@app.route('/atualizar_taxa_manual', methods=['POST'])
def atualizar_taxa_manual():
    from flask import request, redirect, url_for, flash
    nome = request.form.get('nome_taxa')
    valor = request.form.get('valor_taxa')
    if not nome or not valor:
        flash('Nome e valor da taxa são obrigatórios.', 'danger')
        return redirect(url_for('painel_taxas'))
    try:
        # Aceita vírgula ou ponto
        valor_float = float(str(valor).replace(',', '.'))
        from datetime import datetime
        taxa = TaxaReferencia.query.filter_by(nome=nome).order_by(desc(TaxaReferencia.data_atualizacao)).first()
        if taxa:
            taxa.valor = valor_float
            taxa.data_atualizacao = datetime.now()
        else:
            nova_taxa = TaxaReferencia(nome=nome, valor=valor_float, data_atualizacao=datetime.now())
            db.session.add(nova_taxa)
        db.session.commit()
        flash(f'Taxa {nome} atualizada para {valor_float}', 'success')
    except Exception as e:
        flash(f'Erro ao atualizar taxa: {e}', 'danger')
    return redirect(url_for('painel_taxas'))

def parse_decimal_field(field_name, percent_to_decimal=False):
    try:
        raw_value = request.form.get(field_name, '').replace(',', '.').strip()
        if raw_value == '':
            return None
        val = Decimal(raw_value)
        if percent_to_decimal:
            val = val / 100
        return val
    except:
        return None


def parse_int_field(field):
    val = request.form.get(field)
    if val not in (None, '', 'None'):
        try:
            return int(val)
        except Exception:
            return None
    return None

def buscar_taxa_mais_recente(indexador):
    # Busca pelo nome exato, ignorando maiúsculas/minúsculas e espaços
    taxa_ref = TaxaReferencia.query \
        .filter(func.lower(func.trim(TaxaReferencia.nome)) == indexador.strip().lower()) \
        .order_by(desc(TaxaReferencia.data_atualizacao)).first()
    if not taxa_ref:
        # Busca parcial como fallback
        taxa_ref = TaxaReferencia.query \
            .filter(TaxaReferencia.nome.ilike(f"%{indexador.strip()}%")) \
            .order_by(desc(TaxaReferencia.data_atualizacao)).first()
    return taxa_ref

def parse_customizado_amortizacao(raw_value):
    """
    Aceita:
    - JSON válido (lista de números ou dicionários)
    - Lista simples separada por vírgula, ponto e vírgula, espaço ou tabulação
    - Exemplo: '10,20,30,40' ou '[10, 20, 30, 40]'
    Retorna lista de decimais ou None.
    """
    import json
    if not raw_value or str(raw_value).strip() == '':
        return None
    try:
        # Tenta carregar como JSON
        val = json.loads(raw_value)
        if isinstance(val, list):
            return val
        elif isinstance(val, str):
            # Se for string, tenta dividir
            partes = [x.strip() for x in re.split(r'[;,\s]+', val) if x.strip()]
            return [float(p.replace('%','').replace(',','.')) for p in partes]
        else:
            return None
    except Exception:
        # Se não for JSON, tenta dividir como lista simples
        partes = [x.strip() for x in re.split(r'[;,\s]+', raw_value) if x.strip()]
        try:
            return [float(p.replace('%','').replace(',','.')) for p in partes]
        except Exception:
            return None


def clean_decimal_field(raw_value):
    """
    Remove caracteres não numéricos, exceto vírgula e ponto, e converte para Decimal.
    Aceita formatos como 'R$ 1.000,50', '1.000,50', '1000.50', etc.
    """
    from decimal import Decimal, InvalidOperation
    if not raw_value or str(raw_value).strip() == '':
        return None
    # Remove R$, espaços e outros caracteres
    cleaned = re.sub(r'[^0-9,.-]', '', str(raw_value))
    # Se tiver mais de um separador, assume que vírgula é decimal
    if cleaned.count(',') == 1 and cleaned.count('.') > 0:
        cleaned = cleaned.replace('.', '')
    cleaned = cleaned.replace(',', '.')
    try:
        return Decimal(cleaned)
    except InvalidOperation:
        return None

@app.route('/debug_taxa_contrato/<int:id>')
@login_required
def debug_taxa_contrato(id):
    """Rota para debug da taxa de juros de um contrato específico"""
    contrato = Contrato.query.get_or_404(id)
    
    # Informações do contrato
    info_contrato = {
        'id': contrato.id,
        'contrato': contrato.contrato,
        'empresa': contrato.empresa.nome if contrato.empresa else 'N/A',
        'instituicao': contrato.instituicao,
        'modalidade': contrato.modalidade,
        'indexador': contrato.indexador,
        'sistema_amortizacao': contrato.sistema_amortizacao,
        'juros_mensal_banco_raw': str(contrato.juros_mensal) if contrato.juros_mensal else None,
        'juros_mensal_banco_float': float(contrato.juros_mensal) if contrato.juros_mensal else None,
        'juros_mensal_banco_decimal': str(Decimal(str(contrato.juros_mensal))) if contrato.juros_mensal else None,
        'juros_spread_banco': float(contrato.juros_spread) if contrato.juros_spread else None,
        'juros_anual_banco': float(contrato.juros_anual) if contrato.juros_anual else None,
        'juros_pre_banco': float(contrato.juros_pre) if contrato.juros_pre else None,
    }
    
    # Calcular parcelas para obter a taxa usada no cronograma
    resultado = calcular_parcelas(contrato)
    parcelas = resultado['parcelas']
    
    # Pegar a taxa do cronograma (primeira parcela)
    taxa_cronograma = None
    if parcelas:
        taxa_cronograma = parcelas[0].get('juros_percentual', 'N/A')
    
    # Buscar taxa de referência se houver indexador
    taxa_referencia = None
    if contrato.indexador:
        taxa_ref = buscar_taxa_mais_recente(contrato.indexador)
        if taxa_ref:
            taxa_referencia = {
                'nome': taxa_ref.nome,
                'valor': taxa_ref.valor,
                'data_atualizacao': taxa_ref.data_atualizacao.strftime('%d/%m/%Y %H:%M')
            }
    
    # Calcular taxa efetiva baseada na modalidade
    taxa_efetiva_calculada = None
    if contrato.modalidade == 'pre':
        if contrato.juros_mensal:
            taxa_efetiva_calculada = format_taxa_percentual(contrato.juros_mensal)
    elif contrato.modalidade == 'pos':
        if contrato.indexador and contrato.juros_spread:
            # Simular cálculo da taxa pós-fixada
            taxa_ref = buscar_taxa_mais_recente(contrato.indexador)
            if taxa_ref:
                try:
                    taxa_bcb = Decimal(taxa_ref.valor) / Decimal('100')
                    spread = Decimal(str(contrato.juros_spread)) / Decimal('100')
                    taxa_efetiva = (Decimal('1') + taxa_bcb + spread) ** (Decimal('1') / Decimal('12')) - Decimal('1')
                    taxa_efetiva_calculada = format_taxa_percentual(taxa_efetiva)
                except:
                    taxa_efetiva_calculada = "Erro no cálculo"
    
    debug_info = {
        'contrato': info_contrato,
        'taxa_cronograma': taxa_cronograma,
        'taxa_referencia': taxa_referencia,
        'taxa_efetiva_calculada': taxa_efetiva_calculada,
        'primeira_parcela': parcelas[0] if parcelas else None
    }
    
    return jsonify(debug_info)

@app.route('/debug_taxa_visual/<int:id>')
@login_required
def debug_taxa_visual(id):
    """Rota para página visual de debug da taxa de juros"""
    return render_template('debug_taxa.html')

@app.route('/verificar_discrepancias_taxas')
@login_required
def verificar_discrepancias_taxas():
    """Verifica todas as discrepâncias de taxa de juros nos contratos"""
    if not current_user.is_admin:
        flash('Acesso restrito ao administrador.', 'danger')
        return redirect(url_for('index'))
    
    contratos = Contrato.query.all()
    discrepâncias = []
    
    for contrato in contratos:
        try:
            # Calcular parcelas para obter a taxa usada no cronograma
            resultado = calcular_parcelas(contrato)
            parcelas = resultado['parcelas']
            
            if not parcelas:
                continue
                
            taxa_cronograma = parcelas[0].get('juros_percentual', 'N/A')
            
            # Taxa armazenada no banco
            taxa_banco = None
            if contrato.juros_mensal:
                taxa_banco = format_taxa_percentual(contrato.juros_mensal)
            
            # Verificar se há discrepância
            tem_discrepancia = False
            motivo = ""
            
            if contrato.modalidade == 'pre':
                if contrato.juros_mensal and taxa_cronograma != 'N/A':
                    taxa_banco_float = float(contrato.juros_mensal) * 100
                    taxa_cronograma_float = float(taxa_cronograma.replace('%', ''))
                    if abs(taxa_banco_float - taxa_cronograma_float) > 0.0001:  # Tolerância
                        tem_discrepancia = True
                        motivo = f"Taxa banco: {taxa_banco_float:.10f}% vs Cronograma: {taxa_cronograma_float:.10f}%"
            
            elif contrato.modalidade == 'pos':
                if contrato.indexador and contrato.juros_spread:
                    # Para pós-fixado, verificar se a taxa calculada faz sentido
                    taxa_ref = buscar_taxa_mais_recente(contrato.indexador)
                    if taxa_ref:
                        try:
                            taxa_bcb = Decimal(taxa_ref.valor) / Decimal('100')
                            spread = Decimal(str(contrato.juros_spread)) / Decimal('100')
                            taxa_efetiva = (Decimal('1') + taxa_bcb + spread) ** (Decimal('1') / Decimal('12')) - Decimal('1')
                            taxa_esperada = f"{taxa_efetiva * 100:.10f}%"
                            
                            if taxa_cronograma != 'N/A':
                                taxa_cronograma_float = float(taxa_cronograma.replace('%', ''))
                                taxa_esperada_float = float(taxa_efetiva * 100)
                                if abs(taxa_cronograma_float - taxa_esperada_float) > 0.0001:
                                    tem_discrepancia = True
                                    motivo = f"Taxa esperada: {taxa_esperada_float:.10f}% vs Cronograma: {taxa_cronograma_float:.10f}%"
                        except:
                            tem_discrepancia = True
                            motivo = "Erro no cálculo da taxa pós-fixada"
            
            if tem_discrepancia:
                discrepâncias.append({
                    'id': contrato.id,
                    'contrato': contrato.contrato,
                    'empresa': contrato.empresa.nome if contrato.empresa else 'N/A',
                    'instituicao': contrato.instituicao,
                    'modalidade': contrato.modalidade,
                    'indexador': contrato.indexador,
                    'juros_mensal_banco': taxa_banco,
                    'taxa_cronograma': taxa_cronograma,
                    'motivo': motivo
                })
                
        except Exception as e:
            discrepâncias.append({
                'id': contrato.id,
                'contrato': contrato.contrato,
                'empresa': contrato.empresa.nome if contrato.empresa else 'N/A',
                'instituicao': contrato.instituicao,
                'modalidade': contrato.modalidade,
                'indexador': contrato.indexador,
                'juros_mensal_banco': 'Erro',
                'taxa_cronograma': 'Erro',
                'motivo': f"Erro no processamento: {str(e)}"
            })
    
    return render_template('discrepancias_taxas.html', discrepâncias=discrepâncias)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # --- Criar usuário admin se ainda não existir ---
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Usuário admin criado com sucesso!")
        else:
            print("Usuário admin já existe.")
    app.run(host='0.0.0.0', port=5000, debug=True)
