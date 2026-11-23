import os
import sqlite3
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from security import hash_password, verify_password


load_dotenv()

app = Flask(__name__)
DATABASE = "recipes.db"
JWT_SECRET = os.getenv("JWT_SECRET") or "mysecretkey"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    data = {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }
    if "owner" in row.keys():
        data["owner"] = row["owner"]
    return data


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/recipes")
def list_recipes():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing or malformed"}), 401

    token = auth_header.split(" ", 1)[1]

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = decoded["sub"]
    except ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except InvalidTokenError:
        return jsonify({"error": "Invalid token."}), 401

    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
def create_recipe():
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    is_public = 1 if data.get("is_public", True) else 0
    instructions = data.get("instructions", "")

    owner = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            owner = decoded["sub"]
        except (ExpiredSignatureError, InvalidTokenError):
            pass

    db = get_db()
    cols = [r["name"] for r in db.execute("PRAGMA table_info(recipes)").fetchall()]
    try:
        if "owner" in cols:
            cur = db.execute(
                "INSERT INTO recipes (title, ingredients, instructions, is_public, owner) VALUES (?, ?, ?, ?, ?)",
                (data["title"], data["ingredients"], instructions, is_public, owner),
            )
        else:
            cur = db.execute(
                "INSERT INTO recipes (title, ingredients, instructions, is_public) VALUES (?, ?, ?, ?)",
                (data["title"], data["ingredients"], instructions, is_public),
            )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing or malformed"}), 401

    token = auth_header.split(" ", 1)[1]

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = decoded["sub"]
        role = decoded.get("role", "user")
    except ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except InvalidTokenError:
        return jsonify({"error": "Invalid token."}), 401

    db = get_db()
    row = db.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    is_owner = str(row["owner"]) == str(user_id)
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "You do not have permission to edit this recipe"}), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing or malformed"}), 401

    token = auth_header.split(" ", 1)[1]

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = decoded["sub"]
        role = decoded.get("role", "user")
    except ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except InvalidTokenError:
        return jsonify({"error": "Invalid token."}), 401

    db = get_db()
    row = db.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    is_owner = str(row["owner"]) == str(user_id)
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "You do not have permission to delete this recipe"}), 403

    db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    return "", 204


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    db = get_db()
    password_hash = hash_password(password)

    try:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already exists"}), 409

    return jsonify(
        {
            "id": cur.lastrowid,
            "username": username,
            "email": email,
        }
    ), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not password or (not username and not email):
        return jsonify({"error": "username or email and password are required"}), 400

    db = get_db()
    if username:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    else:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user is None or not verify_password(user["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify(
        {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
            },
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
