from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# ToDo model
class ToDo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    is_done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    todos = ToDo.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', todos=todos)

@app.route('/add', methods=['POST'])
@login_required
def add():
    title = request.form['title']
    new_todo = ToDo(title=title, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/update/<int:todo_id>')
@login_required
def update(todo_id):
    todo = ToDo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        flash('You do not have permission to update this item', 'danger')
        return redirect(url_for('dashboard'))
    todo.is_done = not todo.is_done
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:todo_id>')
@login_required
def delete(todo_id):
    todo = ToDo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        flash('You do not have permission to delete this item', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
