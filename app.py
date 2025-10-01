from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import sqlite3
import requests
import hashlib
import secrets
from datetime import datetime
from functools import wraps
import json
import time
import uuid as uuid_lib
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

PTERODACTYL_URL = os.getenv('PTERODACTYL_URL')
PTERODACTYL_API_KEY = os.getenv('PTERODACTYL_API_KEY')
DATABASE_PATH = os.getenv('SQLITE_DATABASE_PATH')

renew_tokens = {}

# Headers pour l'API Pterodactyl
PTERODACTYL_HEADERS = {
    'Authorization': f'Bearer {PTERODACTYL_API_KEY}',
    'Content-Type': 'application/json',
    'Accept': 'Application/vnd.pterodactyl.v1+json'
}

# ==================== DATABASE FUNCTIONS ====================

def get_db_connection():
    """Crée et retourne une connexion à la base de données"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """Fonction générique pour exécuter des requêtes SQL"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    
    result = None
    if fetch_one:
        result = cursor.fetchone()
        result = dict(result) if result else None
    elif fetch_all:
        result = [dict(row) for row in cursor.fetchall()]
    
    if commit:
        conn.commit()
    
    conn.close()
    return result

def init_db():
    """Initialise la base de données"""
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # Table des utilisateurs
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pterodactyl_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS tiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            cpu_limit INTEGER NOT NULL,    
            ram_limit INTEGER NOT NULL, 
            swap_limit INTEGER NOT NULL,     
            disk_limit INTEGER NOT NULL,   
            io_weight INTEGER NOT NULL,         
            database_limit INTEGER NOT NULL,  
            backup_limit INTEGER NOT NULL,
            allocations_limit INTEGER NOT NULL,
            duration_hours INTEGER NOT NULL, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table des serveurs
    c.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tier_id INTEGER NOT NULL,
            server_name TEXT NOT NULL,
            pterodactyl_server_id INTEGER,
            pterodactyl_server_uuid TEXT,
            node_id INTEGER,
            egg_id INTEGER,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            suspended INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
            FOREIGN KEY (tier_id) REFERENCES tiers (id)
        )
    ''')

    # Table de l'historique
    c.execute('''
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        category TEXT NOT NULL,
        action TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

def hash_password(password):
    """Hache un mot de passe"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_tier_by_id(tier_id):
    """Récupère un tier par son ID"""
    return execute_query("SELECT * FROM tiers WHERE id = ?", (tier_id,), fetch_one=True)

def get_all_tiers():
    """Récupère tous les tiers"""
    return execute_query("SELECT * FROM tiers", fetch_all=True)

def get_user_servers(user_id):
    """Récupère tous les serveurs d'un utilisateur"""
    return execute_query(
        "SELECT * FROM servers WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
        fetch_all=True
    )

def get_server_by_uuid(uuid):
    """Récupère un serveur par son UUID"""
    return execute_query(
        "SELECT * FROM servers WHERE pterodactyl_server_uuid = ?",
        (uuid,),
        fetch_one=True
    )

def update_server_status(server_id, suspended, expires_at=None):
    """Met à jour le statut d'un serveur"""
    if expires_at is not None:
        execute_query(
            "UPDATE servers SET suspended = ?, expires_at = ? WHERE id = ?",
            (suspended, expires_at, server_id),
            commit=True
        )
    else:
        execute_query(
            "UPDATE servers SET suspended = ? WHERE id = ?",
            (suspended, server_id),
            commit=True
        )

def delete_server_from_db(pterodactyl_server_id):
    """Supprime un serveur de la base de données"""
    execute_query(
        "DELETE FROM servers WHERE pterodactyl_server_id = ?",
        (pterodactyl_server_id,),
        commit=True
    )

# ==================== PTERODACTYL API FUNCTIONS ====================

def pterodactyl_request(method, endpoint, data=None, params=None):
    """Fonction générique pour les requêtes à l'API Pterodactyl"""
    url = f"{PTERODACTYL_URL}/api/application/{endpoint}"
    
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=PTERODACTYL_HEADERS,
            json=data,
            params=params
        )
        return response
    except Exception as e:
        print(f"Erreur API Pterodactyl ({method} {endpoint}): {e}")
        return None

def create_pterodactyl_user(username, email, password):
    """Crée un utilisateur sur Pterodactyl"""
    data = {
        'username': username,
        'email': email,
        'first_name': username,
        'last_name': 'User',
        'password': password
    }
    
    response = pterodactyl_request('POST', 'users', data=data)
    
    if response and response.status_code == 201:
        return response.json()['attributes']['id']
    
    if response:
        print(f"Erreur création utilisateur Pterodactyl: {response.text}")
    return None

def get_pterodactyl_nodes():
    """Récupère la liste des nœuds Pterodactyl"""
    response = pterodactyl_request('GET', 'nodes', params={'include': 'location'})
    
    if response and response.status_code == 200:
        return response.json()['data']
    return []

def get_pterodactyl_eggs():
    """Récupère la liste des eggs Pterodactyl avec leurs détails complets"""
    response = pterodactyl_request('GET', 'nests')
    
    if not response or response.status_code != 200:
        return []
    
    eggs = []
    nests = response.json()['data']
    
    # Pour chaque nest, récupérer les eggs
    for nest in nests:
        nest_id = nest['attributes']['id']
        eggs_response = pterodactyl_request(
            'GET',
            f"nests/{nest_id}/eggs",
            params={'include': 'variables'}
        )
        
        if eggs_response and eggs_response.status_code == 200:
            nest_eggs = eggs_response.json()['data']
            for egg in nest_eggs:

                user_editable_variables = []
                if 'variables' in egg['attributes']['relationships'] and 'data' in egg['attributes']['relationships']['variables']:
                    user_editable_variables = egg['attributes']['relationships']['variables']['data']
                
                eggs.append({
                    'id': egg['attributes']['id'],
                    'name': egg['attributes']['name'],
                    'docker_image': egg['attributes']['docker_image'],
                    'startup': egg['attributes']['startup'],
                    'variables': {'data': user_editable_variables},
                    'nest': nest['attributes']['name'],
                })
    
    return eggs

def get_egg_details(egg_id):
    """Récupère les détails spécifiques d'un egg"""
    nests_response = pterodactyl_request('GET', 'nests')
    
    if not nests_response or nests_response.status_code != 200:
        return None
    
    nests = nests_response.json()['data']
    
    for nest in nests:
        nest_id = nest['attributes']['id']
        eggs_response = pterodactyl_request(
            'GET',
            f"nests/{nest_id}/eggs/{egg_id}",
            params={'include': 'variables'}
        )
        
        if eggs_response and eggs_response.status_code == 200:
            egg_data = eggs_response.json()['attributes']
            return {
                'docker_image': egg_data['docker_image'],
                'startup': egg_data['startup']
            }
    
    return None

def get_available_allocation(node_id):
    """Récupère une allocation disponible pour le node correspondant"""
    response = pterodactyl_request('GET', f"nodes/{node_id}", params={'include': 'allocations'})
    
    if response and response.status_code == 200:
        allocations = response.json()['attributes']['relationships']['allocations']['data']
        for allocation in allocations:
            if not allocation['attributes']['assigned']:
                return allocation['attributes']['id']
    
    return None

def get_server_details(server_id):
    """Récupère les détails d'un serveur depuis Pterodactyl"""
    response = pterodactyl_request(
        'GET',
        f"servers/{server_id}",
        params={'include': 'egg,location,node,databases,backups,allocations'}
    )
    
    if response and response.status_code == 200:
        return response.json()
    return None

def create_pterodactyl_server(user_pterodactyl_id, server_name, egg_id, node_id, environment, tier_id):
    """Crée un serveur sur Pterodactyl"""
    tier = get_tier_by_id(tier_id)
    if not tier:
        print(f"Tier {tier_id} introuvable")
        return None
    
    egg_details = get_egg_details(egg_id)
    if not egg_details:
        print(f"Impossible de récupérer les détails de l'egg {egg_id}")
        return None
    
    data = {
        'name': server_name,
        'user': user_pterodactyl_id,
        'egg': egg_id,
        'docker_image': egg_details['docker_image'],
        'startup': egg_details['startup'],
        'environment': environment,
        'limits': {
            'memory': tier['ram_limit'],
            'swap': tier['swap_limit'],
            'disk': tier['disk_limit'],
            'io': tier['io_weight'],
            'cpu': tier['cpu_limit']
        },
        'feature_limits': {
            'databases': tier['database_limit'],
            'allocations': tier['allocations_limit'],
            'backups': tier['backup_limit']
        },
        'allocation': {
            'default': get_available_allocation(node_id)
        }
    }
    
    response = pterodactyl_request('POST', 'servers', data=data)
    
    if response and response.status_code == 201:
        attrs = response.json()['attributes']
        return {'uuid': attrs['uuid'], 'id': attrs['id']}
    
    if response:
        print(f"Erreur création serveur: {response.text}")
    return None

def suspend_pterodactyl_server(server_id):
    """Suspend un serveur sur Pterodactyl"""
    response = pterodactyl_request('POST', f"servers/{server_id}/suspend")
    return response and response.status_code == 204

def unsuspend_pterodactyl_server(server_id):
    """Réactive un serveur sur Pterodactyl"""
    response = pterodactyl_request('POST', f"servers/{server_id}/unsuspend")
    return response and response.status_code == 204

def delete_pterodactyl_server(server_id):
    """Supprime un serveur sur Pterodactyl"""
    response = pterodactyl_request('DELETE', f"servers/{server_id}")
    return response and response.status_code == 204

# ==================== DECORATORS ====================

def login_required(f):
    """Décorateur pour vérifier si l'utilisateur est connecté"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Vérification des champs
        if not username or not email or not password:
            flash('Tous les champs sont obligatoires')
            return render_template('register.html')
        
        # Vérifier si l'utilisateur existe déjà
        existing_user = execute_query(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email),
            fetch_one=True
        )
        
        if existing_user:
            execute_query(
                'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
                (None, 'user', 'register', 'failed'),
                commit=True
            )
             
            flash('Nom d\'utilisateur ou email déjà utilisé')
            return render_template('register.html')
        
        # Créer l'utilisateur sur Pterodactyl
        pterodactyl_user_id = create_pterodactyl_user(username, email, password)
        
        if not pterodactyl_user_id:
            flash('Erreur lors de la création du compte')
            
            # Ajouter l'action échouée dans l'historique
            execute_query(
                'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
                (None, 'user', 'register', 'failed'),  
                commit=True
            )
            return render_template('register.html')
        
        # Créer l'utilisateur dans la base de données locale
        password_hash = hash_password(password)
        execute_query(
            'INSERT INTO users (username, email, password_hash, pterodactyl_user_id) VALUES (?, ?, ?, ?)',
            (username, email, password_hash, pterodactyl_user_id),
            commit=True
        )
        
        # Récupérer l'ID de l'utilisateur fraîchement créé
        user_id = execute_query(
            'SELECT id FROM users WHERE username = ?',
            (username,),
            fetch_one=True
        )['id']
        
        # Ajouter l'action réussie dans l'historique
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (user_id, 'user', 'register', 'success'),
            commit=True
        )
        
        flash('Compte créé avec succès!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hash_password(password)
        
        user = execute_query(
            'SELECT id, username, pterodactyl_user_id FROM users WHERE username = ? AND password_hash = ?',
            (username, password_hash),
            fetch_one=True
        )
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['pterodactyl_user_id'] = user['pterodactyl_user_id']

            execute_query(
                'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
                (session['user_id'], 'user', 'login', 'success'),
                commit=True
            )
            
            flash('Connexion réussie!')
            return redirect(url_for('dashboard'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    execute_query(
        'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
        (session['user_id'], 'user', 'logout', 'success'),
        commit=True
    )
    
    session.clear()
    flash('Déconnexion réussie')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    servers = get_user_servers(session['user_id'])
    servers_details = []
    
    for server in servers:
        details = get_server_details(server['pterodactyl_server_id'])
        if details:
            servers_details.append(details)
    
    tiers = get_all_tiers()
    
    return render_template(
        'dashboard.html',
        username=session['username'],
        servers=servers,
        servers_details=servers_details,
        now=round(time.time()),
        tiers=tiers
    )

@app.route('/server/<uuid>/manage')
@login_required
def server_infos(uuid):
    if uuid == "create":
        return redirect(url_for('create_server'))
    
    server = get_server_by_uuid(uuid)
    
    if not server or server['user_id'] != session['user_id']:
        flash('Serveur introuvable')
        return redirect(url_for('dashboard'))
    
    tiers = get_all_tiers()
    server_details = get_server_details(server['pterodactyl_server_id'])
    
    return render_template(
        'server.html',
        tiers=tiers,
        server=server,
        server_details=server_details,
        now=round(time.time())
    )

@app.route('/server/create', methods=['GET', 'POST'])
@login_required
def create_server():
    if request.method == 'POST':
        server_name = request.form['server_name']
        egg_id = int(request.form['egg_id'])
        node_id = int(request.form['node_id'])
        tier_id = int(request.form['tier_id'])
        
        if not server_name:
            execute_query(
                'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
                (session['user_id'], 'server', 'create', 'failed'),
                commit=True
            )

            flash('Le nom du serveur est obligatoire')
            return redirect(url_for('create_server'))
        
        # Extraire les variables d'environnement
        environment = {
            key[4:-1]: value
            for key, value in request.form.items()
            if key.startswith("env[")
        }
        
        # Créer le serveur sur Pterodactyl
        pterodactyl_server_ids = create_pterodactyl_server(
            session['pterodactyl_user_id'],
            server_name,
            egg_id,
            node_id,
            environment,
            tier_id
        )
        
        if not pterodactyl_server_ids:
            execute_query(
                'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
                (session['user_id'], 'server', 'create', 'failed'),
                commit=True
            )

            flash('Erreur lors de la création du serveur sur Pterodactyl')
            return redirect(url_for('create_server'))
        
        # Enregistrer le serveur dans la base de données
        execute_query(
            '''INSERT INTO servers (user_id, server_name, pterodactyl_server_id, 
               pterodactyl_server_uuid, node_id, egg_id, tier_id, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (session['user_id'], server_name, pterodactyl_server_ids['id'],
             pterodactyl_server_ids['uuid'], node_id, egg_id, tier_id, round(time.time())),
            commit=True
        )

        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'create', 'success'),
            commit=True
        )
        
        flash('Serveur créé avec succès!')
        return redirect(url_for('dashboard'))
    
    # Récupérer les nœuds et eggs pour le formulaire
    nodes = get_pterodactyl_nodes()
    eggs = get_pterodactyl_eggs()
    tiers = get_all_tiers()
    
    return render_template('create_server.html', nodes=nodes, eggs=eggs, tiers=tiers)

@app.route('/docs/tiers')
def tiers_infos():
    tiers = get_all_tiers()
    return render_template("tiers.html", tiers=tiers)

@app.route('/server/<uuid>/panel')
def panel_redirect(uuid):
    return redirect(f'https://panel.flowhost.dev/server/{uuid}')

@app.route('/server/<uuid>/renew')
@login_required
def renew_server(uuid):
    execute_query(
        'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
        (session['user_id'], 'server', 'renew', 'pending'),
        commit=True
    )

    token = str(uuid_lib.uuid4())
    renew_tokens[token] = {
        'pterodactyl_server_uuid': uuid,
        'ip': request.remote_addr,
        'ua': request.headers.get('User-Agent'),
        'expire': time.time() + 2 * 60 * 60,
        'created': time.time()
    }
    
    ad_url = "https://link-hub.net/1383828/yHHriFaA5xSk"
    response = make_response(redirect(ad_url))
    response.set_cookie('renew_token', token, max_age=5 * 60, httponly=True, samesite='Lax')
    return response

@app.route('/server/renewed')
@login_required
def validate_renew():
    token = request.cookies.get('renew_token')
    record = renew_tokens.get(token)
    
    # Vérifications initiales
    if not record:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'renew', 'failed'),
            commit=True
        )
        flash("Le renouvellement de votre serveur a expiré. Veuillez renouveler le serveur à nouveau")
        return redirect(url_for('dashboard'))
    
    now = time.time()
    
    if now > record['expire']:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'renew', 'failed'),
            commit=True
        )
        flash("Le renouvellement de votre serveur a expiré. Veuillez renouveler le serveur à nouveau")
        del renew_tokens[token]
        return redirect(url_for('dashboard'))
    
    if record['ip'] != request.remote_addr:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'renew', 'failed'),
            commit=True
        )
        return "IP mismatch", 403
    
    if now - record['created'] < 10:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'renew', 'failed'),
            commit=True
        )
        flash("Le renouvellement de votre serveur n'est pas valide. Veuillez renouveler le serveur à nouveau")
        del renew_tokens[token]
        return redirect(url_for('dashboard'))
    
    pterodactyl_server_uuid = record['pterodactyl_server_uuid']
    
    # Récupérer le serveur
    server = execute_query(
        "SELECT pterodactyl_server_id, tier_id FROM servers WHERE pterodactyl_server_uuid = ?",
        (pterodactyl_server_uuid,),
        fetch_one=True
    )
    
    if not server:
        flash("Serveur introuvable.")
        del renew_tokens[token]
        return redirect(url_for('dashboard'))
    
    # Calculer la nouvelle date d'expiration
    tier = get_tier_by_id(server['tier_id'])
    expire = round(now + tier['duration_hours'] * 3600)
    
    # Mettre à jour la base de données
    execute_query(
        "UPDATE servers SET suspended = 0, expires_at = ? WHERE pterodactyl_server_uuid = ?",
        (expire, pterodactyl_server_uuid),
        commit=True
    )
    
    # Réactiver le serveur sur Pterodactyl
    if unsuspend_pterodactyl_server(server['pterodactyl_server_id']):
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'renew', 'success'),
            commit=True
        )
        flash("Votre serveur a bien été renouvelé")
    else:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'renew', 'failed'),
            commit=True
        )
        flash("Une erreur est survenue lors du renouvellement de votre serveur...")
    
    del renew_tokens[token]
    return redirect(url_for('dashboard'))

@app.route('/server/<id>/delete')
@login_required
def delete_server(id):
    user_servers = get_user_servers(session['user_id'])
    server = next((s for s in user_servers if s['pterodactyl_server_id'] == int(id)), None)
    
    if not server:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'delete', 'failed'),
            commit=True
        )
        flash("Serveur introuvable")
        return redirect(url_for('dashboard'))
    
    # Supprimer le serveur sur Pterodactyl
    if delete_pterodactyl_server(id):
        delete_server_from_db(id)
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'delete', 'success'),
            commit=True
        )
        flash("Serveur supprimé avec succès")
    else:
        execute_query(
            'INSERT INTO history (user_id, category, action, status) VALUES (?, ?, ?, ?)',
            (session['user_id'], 'server', 'delete', 'failed'),
            commit=True
        )
        flash("Erreur lors de la suppression du serveur")
    
    return redirect(url_for('dashboard'))

@app.route('/account/history/', defaults={'page': 1})
@app.route('/account/history/<int:page>')
@login_required
def account_history(page):
    user_id = session['user_id']  # par exemple depuis la session
    if not user_id:
        flash("Utilisateur non connecté")
        return redirect(url_for('login'))

    per_page = 50
    offset = (page - 1) * per_page

    history = execute_query(
        'SELECT category, action, status, created_at '
        'FROM history WHERE user_id = ? '
        'ORDER BY created_at DESC '
        'LIMIT ? OFFSET ?',
        (user_id, per_page, offset),
        fetch_all=True
    )

    total_count = execute_query(
        'SELECT COUNT(*) as count FROM history WHERE user_id = ?',
        (user_id,),
        fetch_one=True
    )['count']

    total_pages = (total_count + per_page - 1) // per_page

    return render_template(
        'history.html',
        history=history,
        page=page,
        total_pages=total_pages
    )

def check_server_availability():
    """Vérifie et suspend les serveurs expirés"""
    servers = execute_query("SELECT * FROM servers", fetch_all=True)
    now = time.time()
    
    for server in servers:
        if int(server['expires_at']) < int(now) and str(server['suspended']) != '1':
            if suspend_pterodactyl_server(server['pterodactyl_server_id']):
                print(f"Serveur {server['pterodactyl_server_id']} mis en maintenance")
                update_server_status(server['id'], 1)

@app.before_request
def auto_task():
    check_server_availability()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True)