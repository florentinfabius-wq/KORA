# Kora — Render Ready

## Déploiement
1. Créez un dépôt GitHub et envoyez tout le contenu de ce dossier à la racine du dépôt.
2. Sur Render : New → Web Service → connectez le dépôt.
3. Runtime : Python.
4. Build Command : `pip install -r requirements.txt`
5. Start Command : `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Health Check : `/api/health`
7. Choisissez Free pour le test.

Le frontend et le backend utilisent automatiquement le même domaine. Le WebSocket passe automatiquement en `wss://` lorsque le site est en HTTPS.

## Important
SQLite est utilisé pour le prototype. Sur une instance Render sans disque persistant, les données locales peuvent être perdues lors d'un redéploiement ou remplacement d'instance. Pour la version production, migrer vers Render PostgreSQL.

Le service WebSocket peut accepter les connexions publiques sur Render.
