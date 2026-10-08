from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3, hashlib, secrets, re, os, json
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "kora.db")
FRONTEND_DIR = BASE_DIR

app = FastAPI(title="Kora API", description="Backend du réseau social Kora", version="4.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_connection():
    c = sqlite3.connect(DATABASE)
    c.row_factory = sqlite3.Row
    return c

def ensure_schema():
    c=get_connection(); cur=c.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT NOT NULL,
        last_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, city TEXT,
        password TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        content TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS friendships(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL, status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL, content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS post_likes(
        id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL, UNIQUE(post_id,user_id))""")
    cur.execute("""CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL, content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        actor_id INTEGER, type TEXT NOT NULL, text TEXT NOT NULL,
        read INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    try: cur.execute("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''")
    except sqlite3.OperationalError: pass
    c.commit(); c.close()

ensure_schema()

def valid_email(e): return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e) is not None
def hash_password(p):
    salt=secrets.token_bytes(16)
    h=hashlib.pbkdf2_hmac("sha256",p.encode(),salt,200_000)
    return f"{salt.hex()}${h.hex()}"
def verify_password(p,s):
    try:
        a,b=s.split("$",1)
        actual=hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(a),200_000)
        return secrets.compare_digest(actual,bytes.fromhex(b))
    except Exception: return False

class RegisterRequest(BaseModel):
    first_name:str; last_name:str; email:str; city:str; password:str
class LoginRequest(BaseModel):
    email:str; password:str
class ProfileUpdate(BaseModel):
    first_name:str; last_name:str; city:str; bio:str=""
class FriendRequest(BaseModel):
    user_id:int; friend_id:int
class PostCreate(BaseModel):
    user_id:int; content:str
class CommentCreate(BaseModel):
    user_id:int; content:str
class MessageCreate(BaseModel):
    sender_id:int; receiver_id:int; content:str

def user_dict(row):
    if not row: return None
    d=dict(row); d.pop("password",None); return d

@app.get("/", include_in_schema=False)
def root(): return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/api/database-test")
def database_test():
    c=get_connection(); rows=c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(); c.close()
    return {"success":True,"database":"SQLite","tables":[r["name"] for r in rows]}

@app.post("/api/users/register")
def register(u:RegisterRequest):
    f,l,e,city=u.first_name.strip(),u.last_name.strip(),u.email.strip().lower(),u.city.strip()
    if not f or not l or not city: raise HTTPException(400,"Prénom, nom et ville obligatoires.")
    if not valid_email(e): raise HTTPException(400,"Adresse email invalide.")
    if len(u.password)<8: raise HTTPException(400,"Le mot de passe doit contenir au moins 8 caractères.")
    c=get_connection()
    if c.execute("SELECT id FROM users WHERE email=?",(e,)).fetchone():
        c.close(); raise HTTPException(409,"Cette adresse email est déjà utilisée.")
    cur=c.execute("INSERT INTO users(first_name,last_name,email,city,password) VALUES(?,?,?,?,?)",(f,l,e,city,hash_password(u.password)))
    uid=cur.lastrowid; c.commit()
    row=c.execute("SELECT id,first_name,last_name,email,city,bio FROM users WHERE id=?",(uid,)).fetchone()
    c.close()
    return {"success":True,"message":"Compte Kora créé avec succès.","user":dict(row)}

@app.post("/api/users/login")
def login(u:LoginRequest):
    e=u.email.strip().lower(); c=get_connection()
    row=c.execute("SELECT * FROM users WHERE email=?",(e,)).fetchone(); c.close()
    if not row or not verify_password(u.password,row["password"]):
        raise HTTPException(401,"Email ou mot de passe incorrect.")
    return {"success":True,"message":"Connexion réussie.","user":user_dict(row)}

@app.get("/api/users")
def users(search:str=""):
    c=get_connection(); q="%"+search.strip()+"%"
    rows=c.execute("""SELECT id,first_name,last_name,email,city,bio FROM users
                      WHERE first_name LIKE ? OR last_name LIKE ? OR city LIKE ?
                      ORDER BY id DESC""",(q,q,q)).fetchall(); c.close()
    return {"success":True,"users":[dict(r) for r in rows]}

@app.get("/api/users/{uid}")
def profile(uid:int):
    c=get_connection(); r=c.execute("SELECT id,first_name,last_name,email,city,bio FROM users WHERE id=?",(uid,)).fetchone()
    if not r: c.close(); raise HTTPException(404,"Utilisateur introuvable.")
    n=c.execute("""SELECT COUNT(*) n FROM friendships WHERE status='accepted' AND (user_id=? OR friend_id=?)""",(uid,uid)).fetchone()["n"]
    c.close(); d=dict(r); d["friends_count"]=n; return {"success":True,"user":d}

@app.put("/api/users/{uid}")
def update_profile(uid:int,d:ProfileUpdate):
    f,l,city=d.first_name.strip(),d.last_name.strip(),d.city.strip()
    if not f or not l or not city: raise HTTPException(400,"Champs obligatoires manquants.")
    c=get_connection()
    if not c.execute("SELECT id FROM users WHERE id=?",(uid,)).fetchone(): c.close(); raise HTTPException(404,"Utilisateur introuvable.")
    c.execute("UPDATE users SET first_name=?,last_name=?,city=?,bio=? WHERE id=?",(f,l,city,d.bio.strip(),uid)); c.commit()
    r=c.execute("SELECT id,first_name,last_name,email,city,bio FROM users WHERE id=?",(uid,)).fetchone(); c.close()
    return {"success":True,"user":dict(r)}

@app.post("/api/friends/request")
def friend_request(d:FriendRequest):
    if d.user_id==d.friend_id: raise HTTPException(400,"Impossible de vous ajouter vous-même.")
    c=get_connection()
    if len(c.execute("SELECT id FROM users WHERE id IN (?,?)",(d.user_id,d.friend_id)).fetchall())!=2:
        c.close(); raise HTTPException(404,"Utilisateur introuvable.")
    old=c.execute("""SELECT * FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)""",
                  (d.user_id,d.friend_id,d.friend_id,d.user_id)).fetchone()
    if old: c.close(); raise HTTPException(409,"Une relation existe déjà.")
    c.execute("INSERT INTO friendships(user_id,friend_id,status) VALUES(?,?, 'pending')",(d.user_id,d.friend_id))
    c.execute("INSERT INTO notifications(user_id,actor_id,type,text) VALUES(?,?,?,?)",(d.friend_id,d.user_id,"friend_request","Vous avez reçu une demande d'amitié."))
    c.commit(); c.close(); return {"success":True,"message":"Demande envoyée."}

@app.get("/api/friends/{uid}")
def friends(uid:int):
    c=get_connection()
    rows=c.execute("""SELECT u.id,u.first_name,u.last_name,u.email,u.city,u.bio
        FROM users u JOIN friendships f ON ((f.user_id=? AND f.friend_id=u.id) OR (f.friend_id=? AND f.user_id=u.id))
        WHERE f.status='accepted' ORDER BY u.first_name""",(uid,uid)).fetchall()
    c.close(); return {"success":True,"friends":[dict(r) for r in rows]}

@app.get("/api/friends/requests/{uid}")
def requests(uid:int):
    c=get_connection()
    rows=c.execute("""SELECT f.id,f.user_id,f.friend_id,u.first_name,u.last_name,u.city
        FROM friendships f JOIN users u ON u.id=f.user_id WHERE f.friend_id=? AND f.status='pending'""",(uid,)).fetchall()
    c.close(); return {"success":True,"requests":[dict(r) for r in rows]}

@app.put("/api/friends/{rid}/{action}")
def respond_friend(rid:int,action:str):
    if action not in ("accept","reject"): raise HTTPException(400,"Action invalide.")
    c=get_connection(); r=c.execute("SELECT * FROM friendships WHERE id=?",(rid,)).fetchone()
    if not r: c.close(); raise HTTPException(404,"Demande introuvable.")
    status="accepted" if action=="accept" else "rejected"
    c.execute("UPDATE friendships SET status=? WHERE id=?",(status,rid))
    if status=="accepted":
        c.execute("INSERT INTO notifications(user_id,actor_id,type,text) VALUES(?,?,?,?)",(r["user_id"],r["friend_id"],"friend_accept","Votre demande d'amitié a été acceptée."))
    c.commit(); c.close(); return {"success":True,"status":status}

@app.post("/api/posts")
def create_post(p:PostCreate):
    text=p.content.strip()
    if not text: raise HTTPException(400,"La publication est vide.")
    c=get_connection()
    if not c.execute("SELECT id FROM users WHERE id=?",(p.user_id,)).fetchone(): c.close(); raise HTTPException(404,"Utilisateur introuvable.")
    cur=c.execute("INSERT INTO posts(user_id,content) VALUES(?,?)",(p.user_id,text)); pid=cur.lastrowid; c.commit()
    r=c.execute("""SELECT p.id,p.user_id,p.content,p.created_at,u.first_name,u.last_name,u.city
                   FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?""",(pid,)).fetchone(); c.close()
    return {"success":True,"post":dict(r)}

@app.get("/api/posts")
def list_posts(user_id:int=0,limit:int=50):
    limit=max(1,min(limit,100)); c=get_connection()
    rows=c.execute(f"""SELECT p.id,p.user_id,p.content,p.created_at,u.first_name,u.last_name,u.city,
                      (SELECT COUNT(*) FROM post_likes x WHERE x.post_id=p.id) likes,
                      (SELECT COUNT(*) FROM comments x WHERE x.post_id=p.id) comments
                      FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT {limit}""").fetchall()
    result=[]
    for r in rows:
        d=dict(r)
        d["liked"]=bool(c.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?",(r["id"],user_id)).fetchone()) if user_id else False
        d["comments_list"]=[dict(x) for x in c.execute("""SELECT c.id,c.user_id,c.content,c.created_at,u.first_name,u.last_name
            FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id""",(r["id"],)).fetchall()]
        result.append(d)
    c.close(); return {"success":True,"posts":result}

@app.delete("/api/posts/{pid}")
def delete_post(pid:int,user_id:int):
    c=get_connection(); r=c.execute("SELECT user_id FROM posts WHERE id=?",(pid,)).fetchone()
    if not r: c.close(); raise HTTPException(404,"Publication introuvable.")
    if r["user_id"]!=user_id: c.close(); raise HTTPException(403,"Vous ne pouvez supprimer que vos publications.")
    c.execute("DELETE FROM post_likes WHERE post_id=?",(pid,)); c.execute("DELETE FROM comments WHERE post_id=?",(pid,)); c.execute("DELETE FROM posts WHERE id=?",(pid,)); c.commit(); c.close()
    return {"success":True}

@app.post("/api/posts/{pid}/like")
def like(pid:int,user_id:int):
    c=get_connection(); exists=c.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?",(pid,user_id)).fetchone()
    if exists:
        c.execute("DELETE FROM post_likes WHERE post_id=? AND user_id=?",(pid,user_id)); liked=False
    else:
        c.execute("INSERT OR IGNORE INTO post_likes(post_id,user_id) VALUES(?,?)",(pid,user_id)); liked=True
        owner=c.execute("SELECT user_id FROM posts WHERE id=?",(pid,)).fetchone()
        if owner and owner["user_id"]!=user_id:
            c.execute("INSERT INTO notifications(user_id,actor_id,type,text) VALUES(?,?,?,?)",(owner["user_id"],user_id,"like","Votre publication a reçu un J'aime."))
    c.commit(); n=c.execute("SELECT COUNT(*) n FROM post_likes WHERE post_id=?",(pid,)).fetchone()["n"]; c.close()
    return {"success":True,"liked":liked,"likes":n}

@app.post("/api/posts/{pid}/comments")
def comment(pid:int,d:CommentCreate):
    text=d.content.strip()
    if not text: raise HTTPException(400,"Commentaire vide.")
    c=get_connection()
    if not c.execute("SELECT id FROM posts WHERE id=?",(pid,)).fetchone(): c.close(); raise HTTPException(404,"Publication introuvable.")
    cur=c.execute("INSERT INTO comments(post_id,user_id,content) VALUES(?,?,?)",(pid,d.user_id,text)); cid=cur.lastrowid
    c.commit(); r=c.execute("""SELECT c.id,c.user_id,c.content,c.created_at,u.first_name,u.last_name
        FROM comments c JOIN users u ON u.id=c.user_id WHERE c.id=?""",(cid,)).fetchone(); c.close()
    return {"success":True,"comment":dict(r)}

@app.get("/api/messages/{uid}")
def conversations(uid:int,with_user:int=0):
    c=get_connection()
    if with_user:
        rows=c.execute("""SELECT id,sender_id,receiver_id,content,created_at FROM messages
          WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
          ORDER BY id""",(uid,with_user,with_user,uid)).fetchall()
    else:
        rows=c.execute("""SELECT id,sender_id,receiver_id,content,created_at FROM messages
          WHERE sender_id=? OR receiver_id=? ORDER BY id DESC LIMIT 100""",(uid,uid)).fetchall()
    c.close(); return {"success":True,"messages":[dict(r) for r in rows]}

connected={}  # uid -> set[WebSocket]

async def push_to_user(uid:int, payload:dict):
    sockets=list(connected.get(uid, set()))
    if not sockets:
        return
    dead=[]
    raw=json.dumps(payload, ensure_ascii=False)
    for sock in sockets:
        try:
            await sock.send_text(raw)
        except Exception:
            dead.append(sock)
    for sock in dead:
        connected.get(uid, set()).discard(sock)

@app.websocket("/ws/{uid}")
async def websocket_endpoint(ws:WebSocket,uid:int):
    await ws.accept()
    connected.setdefault(uid,set()).add(ws)
    try:
        while True:
            data=json.loads(await ws.receive_text())
            target=int(data.get("to",0))
            if target:
                data["from"]=uid
                await push_to_user(target, data)
    except WebSocketDisconnect:
        connected.get(uid,set()).discard(ws)
        if not connected.get(uid):
            connected.pop(uid,None)
    except Exception:
        connected.get(uid,set()).discard(ws)
        if not connected.get(uid):
            connected.pop(uid,None)

@app.post("/api/messages")
async def send_message(m:MessageCreate):
    text=m.content.strip()
    if not text: raise HTTPException(400,"Message vide.")
    c=get_connection(); cur=c.execute("INSERT INTO messages(sender_id,receiver_id,content) VALUES(?,?,?)",(m.sender_id,m.receiver_id,text))
    mid=cur.lastrowid; c.commit(); c.close()
    payload={"type":"message","id":mid,"from":m.sender_id,"to":m.receiver_id,"content":text}
    await push_to_user(m.receiver_id, payload)
    return {"success":True,"message":payload}

@app.get("/api/notifications/{uid}")
def notifications(uid:int):
    c=get_connection(); rows=c.execute("""SELECT id,actor_id,type,text,read,created_at FROM notifications
        WHERE user_id=? ORDER BY id DESC LIMIT 100""",(uid,)).fetchall(); c.close()
    return {"success":True,"notifications":[dict(r) for r in rows]}

@app.put("/api/notifications/{uid}/read")
def mark_notifications(uid:int):
    c=get_connection(); c.execute("UPDATE notifications SET read=1 WHERE user_id=?",(uid,)); c.commit(); c.close()
    return {"success":True}

@app.get("/api/health")
def health(): return {"success":True,"status":"ok","database":DATABASE}


# Fichiers frontend : routes API et WebSocket ci-dessus restent prioritaires.
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
