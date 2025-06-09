from flask import Flask, render_template, request, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from models import db, User, Task

app = Flask(__name__)
app.secret_key = "super‑secret‑key‑change‑me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///tasks.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt = Bcrypt(app)

# ── Flask‑Login setup ───────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"      # redirect here if @login_required fails

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── first‑time DB creation ───────────────────────────────────────
with app.app_context():
    db.create_all()

# ────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    filter_by = request.args.get("filter", "all")
    query = Task.query.filter_by(user_id=current_user.id)

    if filter_by == "completed":
        tasks = query.filter_by(completed=True).all()
    elif filter_by == "active":
        tasks = query.filter_by(completed=False).all()
    else:                                   # "all"
        tasks = query.all()

    return render_template("index.html",
                           tasks=tasks,
                           filter_by=filter_by)

# ── Authentication ──────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        raw_pw   = request.form["password"]

        if User.query.filter_by(username=username).first():
            return "Username already exists – choose another."

        hashed_pw = bcrypt.generate_password_hash(raw_pw).decode("utf‑8")
        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        raw_pw   = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, raw_pw):
            login_user(user)
            return redirect(url_for("index"))
        return "Invalid credentials – try again."

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ── Task CRUD ───────────────────────────────────────────────────
@app.route("/add", methods=["POST"])
@login_required
def add():
    text = request.form.get("task", "").strip()
    if text:
        db.session.add(Task(description=text, user_id=current_user.id))
        db.session.commit()
    return redirect(url_for("index"))


@app.route("/delete/<int:task_id>")
@login_required
def delete(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for("index"))


@app.route("/toggle/<int:task_id>", methods=["POST"])
@login_required
def toggle(task_id):
    task = Task.query.get(task_id)
    if task and task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for("index"))

# ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
