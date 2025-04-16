from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, CSRFError  
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import io
from datetime import datetime

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuration
app.secret_key = os.environ.get('SECRET_KEY') or 'your-strong-secret-key-here'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hidden_gems.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB
app.config['GALLERY_IMAGE_SIZE'] = ("JPG/PNG/GIF, Max 500MB")

# Initialize Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)  
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    places = db.relationship('Place', backref='author', lazy=True)

class Place(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100), nullable=False)
    best_time = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Helper Functions 
def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_image(image):
    """Validate image file with proper error messages"""
    try:
       
        if not image or image.filename == '':
            return False, "No image selected"
            
       
        if not allowed_file(image.filename):
            return False, "Only JPG, PNG or GIF images allowed"
            
       
        image.seek(0, 2)  
        file_size = image.tell()
        image.seek(0)  
        
        max_size = 500 * 1024 * 1024 # 500MB
        if file_size > max_size:
            size_mb = file_size / (1024 * 1024)
            return False, f"Image too large ({size_mb:.1f}MB). Max 500MB allowed"
            
        return True, "Image validated"
        
    except Exception as e:
        return False, f"Error processing image: {str(e)}"

# Template filter 
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%b %d, %Y %I:%M %p'):
    return value.strftime(format)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The form submission was invalid. Please try again.', 'danger')
    return redirect(request.referrer or url_for('home'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email, is_admin=True).first()
        
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['email'] = user.email
            session['username'] = user.first_name
            session['is_admin'] = True
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        
        flash("Invalid admin credentials", "danger")
    
    return render_template("admin_login.html")

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('login'))
    
    all_users = User.query.order_by(User.id).all()
    all_places = Place.query.order_by(Place.timestamp.desc()).all()
    today = datetime.utcnow().date()
    today_places = Place.query.filter(
        db.func.date(Place.timestamp) == today
    ).count()
    
    return render_template("admin_dashboard.html",
                         users=all_users,
                         places=all_places,
                         today_places=today_places)

@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
def toggle_user(user_id):
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash("Cannot modify your own admin status", "danger")
        return redirect(url_for('admin_dashboard'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    action = "promoted to admin" if user.is_admin else "demoted from admin"
    flash(f"User {user.email} has been {action}", "success")
    return redirect(url_for('admin_dashboard'))

@app.before_request
def check_admin_access():
    if request.path.startswith('/admin') and not request.endpoint == 'admin_login':
        if not session.get('is_admin'):
            flash("Admin access required", "danger")
            return redirect(url_for('login'))

# Regular Routes 
@app.route('/')
def home():
    places = Place.query.order_by(Place.timestamp.desc()).all()
    return render_template("home.html", places=places)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    next_page = request.args.get('next')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['email'] = user.email
            session['username'] = user.first_name
            session['is_admin'] = user.is_admin
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        
        flash('Invalid email/password', 'danger')
        return redirect(url_for('login', next=next_page))

    return render_template("login.html", next=next_page)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email').strip().lower()
            existing_user = User.query.filter_by(email=email).first()
            
            if existing_user:
                flash('Email already exists', 'danger')
                return redirect(url_for('register'))

            new_user = User(
                email=email,
                first_name=request.form.get('first_name'),
                password=generate_password_hash(request.form.get('password')),
                is_admin=False
            )
            
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash('Registration failed', 'danger')
    
    return render_template("register.html")

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if session['is_admin']:
        places = Place.query.all()
    else:
        places = Place.query.filter_by(user_id=session['user_id']).all()
    
    return render_template("dashboard.html",
                         places=places,
                         is_admin=session.get('is_admin', False))

@app.route('/add_place', methods=['GET', 'POST'])
def add_place():
    if not session.get('logged_in'):
        return redirect(url_for('login', next=url_for('add_place')))

    if request.method == 'POST':
        try:
        
            if 'image' not in request.files:
                flash('No image selected', 'danger')
                return redirect(request.url)
            
            file = request.files['image']
            is_valid, msg = validate_image(file)
            if not is_valid:
                flash(msg, 'danger')
                return redirect(request.url)
            
           
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            new_place = Place(
                name=request.form.get('name'),
                location=request.form.get('location'),
                description=request.form.get('description'),
                best_time=request.form.get('best_time'),
                image=filename,
                user_id=session['user_id']
            )
            
            db.session.add(new_place)
            db.session.commit()
            flash('Place added successfully!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing request: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template("add_place.html")

@app.route('/edit_place/<int:place_id>', methods=['GET', 'POST'])
def edit_place(place_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    place = Place.query.get_or_404(place_id)

    if not (session['is_admin'] or place.user_id == session['user_id']):
        flash('You cannot edit this place', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            place.name = request.form.get('name')
            place.location = request.form.get('location')
            place.description = request.form.get('description')
            place.best_time = request.form.get('best_time')

            
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename != '':  
                    is_valid, msg = validate_image(file)
                    if not is_valid:
                        flash(msg, 'danger')
                        return redirect(request.url)
                    
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    place.image = filename

            db.session.commit()
            flash('Place updated successfully!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating place: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template("edit_place.html", place=place)

@app.route('/delete_place/<int:place_id>', methods=['POST'])
def delete_place(place_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    place = Place.query.get_or_404(place_id)
    
    if not (session['is_admin'] or place.user_id == session['user_id']):
        flash("You don't have permission to delete this place", "danger")
        return redirect(url_for('dashboard'))

    try:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], place.image)
        if os.path.exists(image_path):
            os.remove(image_path)
            
        db.session.delete(place)
        db.session.commit()
        flash("Place deleted successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting place: {str(e)}", "danger")
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)