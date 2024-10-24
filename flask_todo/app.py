from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

# Set the base path for your project
base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Initialize Flask app and include shared_frontend as a template directory
app = Flask(__name__, template_folder=os.path.join(base_path, 'shared_frontend'))
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

# Serve HTML files from shared_frontend directory
@app.route('/shared_frontend/<path:filename>')
def shared_static(filename):
    return send_from_directory(os.path.join(base_path, 'shared_frontend'), filename)

# Routes to render pages
@app.route('/')
def index():
    return send_from_directory(os.path.join(base_path, 'shared_frontend'), 'index.html')

@app.route('/login.html')
def login_page():
    return send_from_directory(os.path.join(base_path, 'shared_frontend'), 'login.html')

@app.route('/register.html')
def register_page():
    return send_from_directory(os.path.join(base_path, 'shared_frontend'), 'register.html')

@app.route('/dashboard.html')
@login_required
def dashboard_page():
    return send_from_directory(os.path.join(base_path, 'shared_frontend'), 'dashboard.html')

# Routes for authentication
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different username.', 'danger')
            return redirect(url_for('register_page'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard_page'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# REST API Endpoints
@app.route('/api/todos', methods=['GET'])
@login_required
def get_todos():
    todos = ToDo.query.filter_by(user_id=current_user.id).all()
    todos_list = [{'id': todo.id, 'title': todo.title, 'is_done': todo.is_done} for todo in todos]
    return jsonify(todos_list)

@app.route('/api/todos', methods=['POST'])
@login_required
def create_todo():
    data = request.get_json()
    title = data.get('title')
    new_todo = ToDo(title=title, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message': 'To-Do item created successfully'}), 201

@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
@login_required
def update_todo_api(todo_id):
    todo = ToDo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        return jsonify({'error': 'You do not have permission to update this item'}), 403
    data = request.get_json()
    todo.title = data.get('title', todo.title)
    todo.is_done = data.get('is_done', todo.is_done)
    db.session.commit()
    return jsonify({'message': 'To-Do item updated successfully'})

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
@login_required
def delete_todo_api(todo_id):
    todo = ToDo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        return jsonify({'error': 'You do not have permission to delete this item'}), 403
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message': 'To-Do item deleted successfully'})

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
