from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, render_template_string, make_response
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
 
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Hache un mot de passe"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_tier_by_id(tier_id):
    """Récupère un tier par son ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM tiers WHERE id = ?", (tier_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_tiers():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM tiers")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def login_required(f):
    """Décorateur pour vérifier si l'utilisateur est connecté"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def create_pterodactyl_user(username, email, password):
    """Crée un utilisateur sur Pterodactyl"""
    try:
        data = {
            'username': username,
            'email': email,
            'first_name': username,
            'last_name': 'User',
            'password': password
        }
        
        response = requests.post(
            f"{PTERODACTYL_URL}/api/application/users",
            headers=PTERODACTYL_HEADERS,
            json=data
        )
        
        if response.status_code == 201:
            return response.json()['attributes']['id']
        else:
            print(f"Erreur création utilisateur Pterodactyl: {response.text}")
            return None
    except Exception as e:
        print(f"Erreur API Pterodactyl: {e}")
        return None

def get_pterodactyl_nodes():
    """Récupère la liste des nœuds Pterodactyl"""
    try:
        params = {
            'include':'location'
        }

        response = requests.get(
            f"{PTERODACTYL_URL}/api/application/nodes",
            headers=PTERODACTYL_HEADERS, params=params
        )
        
        if response.status_code == 200:
            return response.json()['data']
        return []
    except Exception as e:
        print(f"Erreur récupération nœuds: {e}")
        return []

def get_pterodactyl_eggs():
    """Récupère la liste des eggs Pterodactyl avec leurs détails complets"""
    try:
        response = requests.get(
            f"{PTERODACTYL_URL}/api/application/nests",
            headers=PTERODACTYL_HEADERS
        )
        
        if response.status_code == 200:
            eggs = []
            nests = response.json()['data']
            
            # Pour chaque nest, récupérer les eggs
            for nest in nests:
                nest_id = nest['attributes']['id']
                params = {'include': 'variables'}
                eggs_response = requests.get(
                    f"{PTERODACTYL_URL}/api/application/nests/{nest_id}/eggs",
                    headers=PTERODACTYL_HEADERS, params=params
                )
                
                if eggs_response.status_code == 200:
                    nest_eggs = eggs_response.json()['data']
                    for egg in nest_eggs:
                        # Filtrer les variables pour ne garder que celles modifiables par l'utilisateur
                        user_editable_variables = []
                        if 'variables' in egg['attributes']['relationships'] and 'data' in egg['attributes']['relationships']['variables']:
                            for var in egg['attributes']['relationships']['variables']['data']:
                                user_editable_variables.append(var)
                        
                        eggs.append({
                            'id': egg['attributes']['id'],
                            'name': egg['attributes']['name'],
                            'docker_image': egg['attributes']['docker_image'],
                            'startup': egg['attributes']['startup'],
                            'variables': {
                                'data': user_editable_variables
                            },
                            'nest': nest['attributes']['name'],
                        })
            
            return eggs
        return []
    except Exception as e:
        print(f"Erreur récupération eggs: {e}")
        return []

def get_egg_details(egg_id):
    """Récupère les détails spécifiques d'un egg"""
    try:
        # D'abord, trouver le nest qui contient cet egg
        nests_response = requests.get(
            f"{PTERODACTYL_URL}/api/application/nests",
            headers=PTERODACTYL_HEADERS
        )
        
        if nests_response.status_code != 200:
            return None
            
        nests = nests_response.json()['data']
        
        for nest in nests:
            nest_id = nest['attributes']['id']
            params = {'include': 'variables'}
            eggs_response = requests.get(
                f"{PTERODACTYL_URL}/api/application/nests/{nest_id}/eggs/{egg_id}",
                headers=PTERODACTYL_HEADERS, params=params
            )
            
            if eggs_response.status_code == 200:
                egg_data = eggs_response.json()['attributes']
                return {
                    'docker_image': egg_data['docker_image'],
                    'startup': egg_data['startup']
                }
        
        return None
    except Exception as e:
        print(f"Erreur récupération détails egg: {e}")
        return None

def get_available_allocation(node_id):
    """Récupère une allocation disponible pour le node correspondant"""
    try:
        params = {
            'include':'allocations'
        }

        response = requests.get(
            f"{PTERODACTYL_URL}/api/application/nodes/{node_id}",
            headers=PTERODACTYL_HEADERS, params=params
        )
        
        if response.status_code == 200:
            for allocation in response.json()['attributes']['relationships']['allocations']['data']:
                if not allocation['attributes']['assigned']:
                    return allocation['attributes']['id']    
        return []
    except Exception as e:
        print(f"Erreur récupération nœuds: {e}")
        return []

def get_server_details(id):
    params = {
            'include':'egg,location,node,databases,backups, allocations'
        }

    response = requests.get(
        f"{PTERODACTYL_URL}/api/application/servers/{id}",
        headers=PTERODACTYL_HEADERS, params=params
    )

    if response.status_code == 200:
        return response.json()
    else:
        return None

def create_pterodactyl_server(user_pterodactyl_id, server_name, egg_id, node_id, environment, tier_id):
    """Crée un serveur sur Pterodactyl"""
    try:
        # Récupérer les détails de l'egg
        tier = get_tier_by_id(tier_id)

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
        
        response = requests.post(
            f"{PTERODACTYL_URL}/api/application/servers",
            headers=PTERODACTYL_HEADERS,
            json=data
        )
        
        if response.status_code == 201:
            return {'uuid':response.json()['attributes']['uuid'],'id':response.json()['attributes']['id']} 
        else:
            print(f"Erreur création serveur: {response.text}")
            return None
    except Exception as e:
        print(f"Erreur création serveur: {e}")
        return None

def get_user_servers(user_id):
    """Récupère tous les serveurs d'un utilisateur (toutes les colonnes)"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # permet un dict propre
    c = conn.cursor()
    
    c.execute('''
        SELECT *
        FROM servers
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,))
    
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]
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
        
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        # Vérifier si l'utilisateur existe déjà
        c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if c.fetchone():
            flash('Nom d\'utilisateur ou email déjà utilisé')
            conn.close()
            return render_template('register.html')
        
        # Créer l'utilisateur sur Pterodactyl
        pterodactyl_user_id = create_pterodactyl_user(username, email, password)
        
        if not pterodactyl_user_id:
            flash('Erreur lors de la création du compte Pterodactyl')
            conn.close()
            return render_template('register.html')
        
        # Créer l'utilisateur dans la base de données locale
        password_hash = hash_password(password)
        c.execute('''
            INSERT INTO users (username, email, password_hash, pterodactyl_user_id)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, pterodactyl_user_id))
        
        conn.commit()
        conn.close()
        
        flash('Compte créé avec succès!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        password_hash = hash_password(password)
        c.execute('''
            SELECT id, username, pterodactyl_user_id 
            FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))
        
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['pterodactyl_user_id'] = user[2]
            flash('Connexion réussie!')
            return redirect(url_for('dashboard'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Déconnexion réussie')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    servers = get_user_servers(session['user_id'])
    servers_details = []
    tiers = get_all_tiers()

    for server in servers:
        details = get_server_details(server['pterodactyl_server_id'])
        servers_details.append(details)

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

    user_servers = get_user_servers(session['user_id'])

    server = next((s for s in user_servers if s['pterodactyl_server_uuid'] == uuid), None)

    if server:
        tiers = get_all_tiers()
        server_details = get_server_details(server['pterodactyl_server_id'])
        
        return render_template('server.html', tiers=tiers, server=server, server_details=server_details, now=round(time.time()))

    flash('Serveur introuvable')
    return redirect(url_for('dashboard'))

@app.route('/server/create', methods=['GET', 'POST'])
@login_required
def create_server():
    if request.method == 'POST':
        server_name = request.form['server_name']
        egg_id = int(request.form['egg_id'])
        node_id = int(request.form['node_id'])
        tier_id = int(request.form['tier_id'])
        
        if not server_name:
            flash('Le nom du serveur est obligatoire')
            return redirect(url_for('create_server'))
        
        environment = {
            key[4:-1]: value   # enlève "env[" et "]"
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
            flash('Erreur lors de la création du serveur sur Pterodactyl')
            return redirect(url_for('create_server'))
        
        # Enregistrer le serveur dans la base de données
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO servers (user_id, server_name, pterodactyl_server_id, pterodactyl_server_uuid, node_id, egg_id, tier_id, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], server_name, pterodactyl_server_ids['id'], pterodactyl_server_ids['uuid'], node_id, egg_id, tier_id, round(time.time())))
        
        conn.commit()
        conn.close()
        
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
def renew_server(uuid):
    token = str(uuid_lib.uuid4())
    renew_tokens[token] = {
        'pterodactyl_server_uuid': uuid,
        'ip':request.remote_addr,
        'ua':request.headers.get('User-Agent'),
        'expire': time.time()+ 2*60*60,
        'created': time.time()
    }
    ad_url = "https://link-hub.net/1383828/yHHriFaA5xSk"
    response = make_response(redirect(ad_url))
    response.set_cookie('renew_token', token, max_age=5*60, httponly=True, samesite='Lax')
    return response

@app.route('/server/renewed')
def validate_renew():
    token = request.cookies.get('renew_token')
    record = renew_tokens.get(token)

    # Vérifications initiales
    if not record:
        flash("Le renouvellement de votre serveur a expiré. Veuillez renouveler le serveur à nouveau")
        return redirect(url_for('dashboard'))

    now = time.time()

    if now > record['expire']:
        flash("Le renouvellement de votre serveur a expiré. Veuillez renouveler le serveur à nouveau")
        del renew_tokens[token]
        return redirect(url_for('dashboard'))

    if record['ip'] != request.remote_addr:
        return "IP mismatch", 403

    if now - record['created'] < 10:
        flash("Le renouvellement de votre serveur n'est pas valide. Veuillez renouveler le serveur à nouveau")
        del renew_tokens[token]
        return redirect(url_for('dashboard'))

    pterodactyl_server_uuid = record['pterodactyl_server_uuid']

    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT pterodactyl_server_id, tier_id FROM servers WHERE pterodactyl_server_uuid = ?",
            (pterodactyl_server_uuid,)
        )
        row = cursor.fetchone()
        if not row:
            flash("Serveur introuvable.")
            return redirect(url_for('dashboard'))

        server_id, tier_id = row

        expire = round(now + get_tier_by_id(tier_id)['duration_hours'] * 3600)

        cursor.execute(
            "UPDATE servers SET suspended = 0, expires_at = ? WHERE pterodactyl_server_uuid = ?",
            (expire, pterodactyl_server_uuid)
        )

    response = requests.post(
        f"{PTERODACTYL_URL}/api/application/servers/{server_id}/unsuspend",
        headers=PTERODACTYL_HEADERS
    )

    if response.status_code == 204:
        flash("Votre serveur a bien été renouvelé")
    else:
        flash("Une erreur est survenue lors du renouvellement de votre serveur...")

    del renew_tokens[token]

    return redirect(url_for('dashboard'))



def check_server_availability():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM servers")
    rows = cursor.fetchall()
    servers = [dict(row) for row in rows]

    now = time.time()

    for server in servers:
        if int(server['expires_at']) < int(now) and str(server['suspended']) != '1':
            response = requests.post(
                f"{PTERODACTYL_URL}/api/application/servers/{server['pterodactyl_server_id']}/suspend",
                headers=PTERODACTYL_HEADERS
            )
            if response.status_code == 204:
                print(f"Serveur {server['pterodactyl_server_id']} mis en maintenance")
                cursor.execute(
                    "UPDATE servers SET suspended = 1 WHERE id = ?",
                    (server['id'],)
                )
                conn.commit()  

    conn.close()

@app.route('/server/<id>/delete')  
def delete_server(id):
    user_servers = get_user_servers(session['user_id'])

    print(user_servers)
    print(id)

    server = next((s for s in user_servers if s['pterodactyl_server_id'] == int(id)), None)

    if server:      
        response = requests.delete(
            f"{PTERODACTYL_URL}/api/application/servers/{id}",
            headers=PTERODACTYL_HEADERS
        )
        if response.status_code == 204:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM servers WHERE pterodactyl_server_id = ?", (id,))
            conn.commit()
            conn.close()

            flash("Serveur supprimé avec succès")
        else:
            flash("Erreur lors de la suppresion du serveur")
    else:
        flash("Serveur introuvable")
    return redirect(url_for('dashboard'))




@app.before_request
def auto_task():
    check_server_availability()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)