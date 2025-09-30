z='renew_token'
y='created'
x='expire'
w='Serveur introuvable'
v='pterodactyl_user_id'
u='email'
t='login'
q='pterodactyl_server_uuid'
p='create_server'
o='GET'
n='uuid'
m='allocations'
l='password'
k=None
g='pterodactyl_server_id'
f='name'
e='relationships'
d=round
c=dict
b='include'
a='username'
Y='POST'
X='startup'
W='docker_image'
V='variables'
U=int
T=Exception
S='user_id'
Q='data'
P='dashboard'
O='id'
N='pterodactyl_app.db'
L=print
C='attributes'
from flask import Flask,render_template as M,request as D,redirect as B,url_for as E,session as H,flash as A,jsonify,render_template_string,make_response as A0
import sqlite3 as G,requests as I,hashlib,secrets
from datetime import datetime
from functools import wraps
import json,time as R,uuid as A1
F=Flask(__name__)
F.secret_key='votre_cle_secrete_ici'
J='https://panel.flowhost.dev'
A2='ptla_M1Vo0F36sab3rYEA0HEvWsFNSdYQkBz77B2WMVVZTHP'
Z={}
K={'Authorization':f"Bearer {A2}",'Content-Type':'application/json','Accept':'Application/vnd.pterodactyl.v1+json'}
def A3():A=G.connect(N);B=A.cursor();B.execute('\n        CREATE TABLE IF NOT EXISTS users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE NOT NULL,\n            email TEXT UNIQUE NOT NULL,\n            password_hash TEXT NOT NULL,\n            pterodactyl_user_id INTEGER,\n            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n        )\n    ');B.execute('\n        CREATE TABLE IF NOT EXISTS tiers (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            name TEXT UNIQUE NOT NULL,\n            cpu_limit INTEGER NOT NULL,    \n            ram_limit INTEGER NOT NULL, \n            swap_limit INTEGER NOT NULL,     \n            disk_limit INTEGER NOT NULL,   \n            io_weight INTEGER NOT NULL,         \n            database_limit INTEGER NOT NULL,  \n            backup_limit INTEGER NOT NULL,\n            allocations_limit INTEGER NOT NULL,\n            duration_hours INTEGER NOT NULL, \n            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n        )\n    ');B.execute('\n        CREATE TABLE IF NOT EXISTS servers (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            user_id INTEGER NOT NULL,\n            tier_id INTEGER NOT NULL,\n            server_name TEXT NOT NULL,\n            pterodactyl_server_id INTEGER,\n            pterodactyl_server_uuid TEXT,\n            node_id INTEGER,\n            egg_id INTEGER,\n            expires_at TIMESTAMP NOT NULL,\n            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n            suspended INTEGER,\n            FOREIGN KEY (user_id) REFERENCES users (id)\n            FOREIGN KEY (tier_id) REFERENCES tiers (id)\n        )\n    ');A.commit();A.close()
def r(password):return hashlib.sha256(password.encode()).hexdigest()
def s(tier_id):A=G.connect(N);A.row_factory=G.Row;B=A.cursor();B.execute('SELECT * FROM tiers WHERE id = ?',(tier_id,));C=B.fetchone();A.close();return c(C)if C else k
def h():A=G.connect(N);A.row_factory=G.Row;B=A.cursor();B.execute('SELECT * FROM tiers');C=B.fetchall();A.close();return[c(A)for A in C]
def i(f):
	@wraps(f)
	def A(*A,**C):
		if S not in H:return B(E(t))
		return f(*A,**C)
	return A
def A4(username,email,password):
	B=username
	try:
		D={a:B,u:email,'first_name':B,'last_name':'User',l:password};A=I.post(f"{J}/api/application/users",headers=K,json=D)
		if A.status_code==201:return A.json()[C][O]
		else:L(f"Erreur création utilisateur Pterodactyl: {A.text}");return
	except T as E:L(f"Erreur API Pterodactyl: {E}");return
def A5():
	try:
		B={b:'location'};A=I.get(f"{J}/api/application/nodes",headers=K,params=B)
		if A.status_code==200:return A.json()[Q]
		return[]
	except T as C:L(f"Erreur récupération nœuds: {C}");return[]
def A6():
	try:
		B=I.get(f"{J}/api/application/nests",headers=K)
		if B.status_code==200:
			D=[];M=B.json()[Q]
			for E in M:
				N=E[C][O];P={b:V};F=I.get(f"{J}/api/application/nests/{N}/eggs",headers=K,params=P)
				if F.status_code==200:
					R=F.json()[Q]
					for A in R:
						G=[]
						if V in A[C][e]and Q in A[C][e][V]:
							for H in A[C][e][V][Q]:
								if H[C].get('user_editable',False):G.append(H)
						D.append({O:A[C][O],f:A[C][f],W:A[C][W],X:A[C][X],V:{Q:G},'nest':E[C][f]})
			return D
		return[]
	except T as S:L(f"Erreur récupération eggs: {S}");return[]
def A7(egg_id):
	try:
		A=I.get(f"{J}/api/application/nests",headers=K)
		if A.status_code!=200:return
		E=A.json()[Q]
		for F in E:
			G=F[C][O];H={b:V};B=I.get(f"{J}/api/application/nests/{G}/eggs/{egg_id}",headers=K,params=H)
			if B.status_code==200:D=B.json()[C];return{W:D[W],X:D[X]}
		return
	except T as M:L(f"Erreur récupération détails egg: {M}");return
def A8(node_id):
	try:
		D={b:m};A=I.get(f"{J}/api/application/nodes/{node_id}",headers=K,params=D)
		if A.status_code==200:
			for B in A.json()[C][e][m][Q]:
				if not B[C]['assigned']:return B[C][O]
		return[]
	except T as E:L(f"Erreur récupération nœuds: {E}");return[]
def A9(id):
	B={b:'egg,location,node,databases,backups'};A=I.get(f"{J}/api/application/servers/{id}",headers=K,params=B)
	if A.status_code==200:return A.json()
	else:return
def AA(user_pterodactyl_id,server_name,egg_id,node_id,environment,tier_id):
	D=egg_id
	try:
		A=s(tier_id);E=A7(D)
		if not E:L(f"Impossible de récupérer les détails de l'egg {D}");return
		F={f:server_name,'user':user_pterodactyl_id,'egg':D,W:E[W],X:E[X],'environment':environment,'limits':{'memory':A['ram_limit'],'swap':A['swap_limit'],'disk':A['disk_limit'],'io':A['io_weight'],'cpu':A['cpu_limit']},'feature_limits':{'databases':A['database_limit'],m:A['allocations_limit'],'backups':A['backup_limit']},'allocation':{'default':A8(node_id)}};B=I.post(f"{J}/api/application/servers",headers=K,json=F)
		if B.status_code==201:return{n:B.json()[C][n],O:B.json()[C][O]}
		else:L(f"Erreur création serveur: {B.text}");return
	except T as G:L(f"Erreur création serveur: {G}");return
def j(user_id):A=G.connect(N);A.row_factory=G.Row;B=A.cursor();B.execute('\n        SELECT *\n        FROM servers\n        WHERE user_id = ?\n        ORDER BY created_at DESC\n    ',(user_id,));C=B.fetchall();A.close();return[c(A)for A in C]
@F.route('/')
def AC():
	if S in H:return B(E(P))
	return M('index.html')
@F.route('/register',methods=[o,Y])
def AD():
	I='register.html'
	if D.method==Y:
		F=D.form[a];H=D.form[u];J=D.form[l]
		if not F or not H or not J:A('Tous les champs sont obligatoires');return M(I)
		C=G.connect(N);K=C.cursor();K.execute('SELECT id FROM users WHERE username = ? OR email = ?',(F,H))
		if K.fetchone():A("Nom d'utilisateur ou email déjà utilisé");C.close();return M(I)
		L=A4(F,H,J)
		if not L:A('Erreur lors de la création du compte Pterodactyl');C.close();return M(I)
		O=r(J);K.execute('\n            INSERT INTO users (username, email, password_hash, pterodactyl_user_id)\n            VALUES (?, ?, ?, ?)\n        ',(F,H,O,L));C.commit();C.close();A('Compte créé avec succès!');return B(E(t))
	return M(I)
@F.route('/login',methods=[o,Y])
def AE():
	if D.method==Y:
		J=D.form[a];K=D.form[l];F=G.connect(N);I=F.cursor();L=r(K);I.execute('\n            SELECT id, username, pterodactyl_user_id \n            FROM users \n            WHERE username = ? AND password_hash = ?\n        ',(J,L));C=I.fetchone();F.close()
		if C:H[S]=C[0];H[a]=C[1];H[v]=C[2];A('Connexion réussie!');return B(E(P))
		else:A("Nom d'utilisateur ou mot de passe incorrect")
	return M('login.html')
@F.route('/logout')
def AF():H.clear();A('Déconnexion réussie');return B(E('index'))
@F.route('/dashboard')
@i
def AG():A=j(H[S]);return M('dashboard.html',username=H[a],servers=A,now=d(R.time()))
@F.route('/server/<uuid>/manage')
@i
def AH(uuid):
	if uuid=='create':return B(E(p))
	D=j(H[S]);C=next((A for A in D if A[q]==uuid),k)
	if C:F=h();G=A9(C[g]);return M('server.html',tiers=F,server=C,server_details=G,now=d(R.time()))
	A(w);return B(E(P))
@F.route('/server/create',methods=[o,Y])
@i
def AI():
	if D.method==Y:
		C=D.form['server_name'];J=U(D.form['egg_id']);K=U(D.form['node_id']);L=U(D.form['tier_id'])
		if not C:A('Le nom du serveur est obligatoire');return B(E(p))
		Q={A[4:-1]:B for(A,B)in D.form.items()if A.startswith('env[')};F=AA(H[v],C,J,K,Q,L)
		if not F:A('Erreur lors de la création du serveur sur Pterodactyl');return B(E(p))
		I=G.connect(N);T=I.cursor();T.execute('\n            INSERT INTO servers (user_id, server_name, pterodactyl_server_id, pterodactyl_server_uuid, node_id, egg_id, tier_id, expires_at)\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?)\n        ',(H[S],C,F[O],F[n],K,J,L,d(R.time())));I.commit();I.close();A('Serveur créé avec succès!');return B(E(P))
	V=A5();W=A6();X=h();return M('create_server.html',nodes=V,eggs=W,tiers=X)
@F.route('/docs/tiers')
def AJ():A=h();return M('tiers.html',tiers=A)
@F.route('/server/<uuid>/panel')
def AK(uuid):return B(f"https://panel.flowhost.dev/server/{uuid}")
@F.route('/server/<uuid>/renew')
def AL(uuid):A=str(A1.uuid4());Z[A]={q:uuid,'ip':D.remote_addr,'ua':D.headers.get('User-Agent'),x:R.time()+7200,y:R.time()};E='https://link-hub.net/1383828/yHHriFaA5xSk';C=A0(B(E));C.set_cookie(z,A,max_age=300,httponly=True,samesite='Lax');return C
@F.route('/server/renewed')
def AM():
	Q='Le renouvellement de votre serveur a expiré. Veuillez renouveler le serveur à nouveau';F=D.cookies.get(z);C=Z.get(F)
	if not C:A(Q);return B(E(P))
	H=R.time()
	if H>C[x]:A(Q);del Z[F];return B(E(P))
	if C['ip']!=D.remote_addr:return'IP mismatch',403
	if H-C[y]<10:A("Le renouvellement de votre serveur n'est pas valide. Veuillez renouveler le serveur à nouveau");del Z[F];return B(E(P))
	M=C[q]
	with G.connect(N)as S:
		L=S.cursor();L.execute('SELECT pterodactyl_server_id, tier_id FROM servers WHERE pterodactyl_server_uuid = ?',(M,));O=L.fetchone()
		if not O:A('Serveur introuvable.');return B(E(P))
		T,U=O;V=d(H+s(U)['duration_hours']*3600);L.execute('UPDATE servers SET suspended = 0, expires_at = ? WHERE pterodactyl_server_uuid = ?',(V,M))
	W=I.post(f"{J}/api/application/servers/{T}/unsuspend",headers=K)
	if W.status_code==204:A('Votre serveur a bien été renouvelé')
	else:A('Une erreur est survenue lors du renouvellement de votre serveur...')
	del Z[F];return B(E(P))
def AB():
	B=G.connect(N);B.row_factory=G.Row;C=B.cursor();C.execute('SELECT * FROM servers');D=C.fetchall();E=[c(A)for A in D];F=R.time()
	for A in E:
		if U(A['expires_at'])<U(F)and str(A['suspended'])!='1':
			H=I.post(f"{J}/api/application/servers/{A[g]}/suspend",headers=K)
			if H.status_code==204:L(f"Serveur {A[g]} mis en maintenance");C.execute('UPDATE servers SET suspended = 1 WHERE id = ?',(A[O],));B.commit()
	B.close()
@F.route('/server/<id>/delete')
def AN(id):
	D=j(H[S]);L(D);L(id);F=next((A for A in D if A[g]==U(id)),k)
	if F:
		M=I.delete(f"{J}/api/application/servers/{id}",headers=K)
		if M.status_code==204:C=G.connect(N);O=C.cursor();O.execute('DELETE FROM servers WHERE pterodactyl_server_id = ?',(id,));C.commit();C.close();A('Serveur supprimé avec succès')
		else:A('Erreur lors de la suppresion du serveur')
	else:A(w)
	return B(E(P))
@F.before_request
def AO():AB()
if __name__=='__main__':A3();F.run(debug=True)