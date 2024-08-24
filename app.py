from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash,
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from utils import *
from config import SECRET_KEY
from model import (
    get_user_chat_historys,
    get_user_chat,
    User,
    create_user,
    authenticate_user,
)
from bson import ObjectId


app = Flask(__name__)

app.secret_key = SECRET_KEY
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


@login_manager.user_loader
def load_user(user_id):
    print(f"Attempting to load user with id: {user_id}")  # 디버그 출력
    user = User.get(user_id)
    print(f"Loading user: {user}")  # 디버그 출력
    return User.get(ObjectId(user_id))


@app.route("/")
@login_required
def chat():
    history = get_user_chat_historys("hang13")
    print(f"User {current_user.id} is accessing the chat page.")  # 디버그 출력
    return render_template("chat.html", history=history)


@app.route("/check_auth")
def check_auth():
    return jsonify({"authenticated": current_user.is_authenticated})


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = authenticate_user(email, password)
        if user:
            login_user(user)
            session["user_id"] = str(user.id)
            print(f"User {user.id} logged in successfully.")  # 디버그 출력
            return redirect(url_for("chat"))
        else:
            print("Authentication failed.")  # 디버그 출력
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    print(f"User {current_user.id} is logging out.")  # 디버그 출력
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        user = create_user(username, email, password)
        if user:
            login_user(user)
            print(f"User {user.id} registered and logged in.")  # 디버그 출력
            return redirect(url_for("login"))
        else:
            flash("already user exists")
            print("User registration failed: already exists.")  # 디버그 출력
    return render_template("register.html")


@app.route("/get_response", methods=["POST"])
@login_required
def get_response():
    if not current_user.is_authenticated:
        return jsonify({"error": "Unauthorized"}), 401
    # 유저가 보낸 메시지를 받음
    user_input = request.json.get("message")
    print(f"User {current_user.id} sent a message: {user_input}")  # 디버그 출력

    chat_history = session.get("chat_history", "")

    ai_response, chat_history = get_ai_response(user_input, chat_history)
    ai_response = ai_response.replace("\n", "<br>")

    session["chat_history"] = chat_history

    # JSON 형태로 응답을 반환
    return jsonify({"response": ai_response})


@app.route("/history/<history_id>")
@login_required
def history(history_id):
    history = get_user_chat_historys("hang13")
    chat = get_user_chat(history_id)

    for ct in chat:
        ct["user"] = ct["user"].replace("\n", "<br>")
        ct["ai"] = ct["ai"].replace("\n", "<br>")

    print(f"User {current_user.id} is viewing history {history_id}.")  # 디버그 출력
    return render_template("history.html", history=history, chat=chat)


if __name__ == "__main__":
    app.run(debug=True)
