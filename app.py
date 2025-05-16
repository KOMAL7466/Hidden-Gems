from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, CSRFError  
from flask_wtf.csrf import generate_csrf
from flask_login import current_user, LoginManager, UserMixin
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import io
from datetime import datetime, timezone, timedelta
import pytz
IST = pytz.timezone('Asia/Kolkata')
import requests
import numpy as np
from sklearn.linear_model import LinearRegression
import pickle
from geopy.distance import geodesic
from time import sleep
import json
from geopy.geocoders import Nominatim
from geopy.extra.rate_limiter import RateLimiter
from sklearn.ensemble import RandomForestRegressor
import joblib
import pandas as pd
from flask import jsonify


geolocator = Nominatim(user_agent="hidden_gems_app")
geocode = RateLimiter(geolocator.geocode, min_delay_seconds=1)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuration
app.secret_key = os.environ.get('SECRET_KEY') or 'your-strong-secret-key-here'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hidden_gems.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['WEATHER_API_KEY'] = '132a84233e6088a664b73e0ed8e91b7c'  
app.config['CROWD_PREDICTION_MODEL_PATH'] = 'crowd_prediction_model.pkl'

# Initialize Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
login_manager = LoginManager(app) 

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs("crowd_models", exist_ok=True)

# Database Models 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_permanent_admin = db.Column(db.Boolean, default=False) 
    places = db.relationship('Place', backref='author', lazy=True)
    
class Place(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100), nullable=False)
    best_time = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(IST))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    visit_history = db.relationship('PlaceVisit', backref='place', lazy=True)

class PlaceVisit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    place_id = db.Column(db.Integer, db.ForeignKey('place.id'))
    visit_date = db.Column(db.DateTime, default=lambda: datetime.now(IST))
    day_of_week = db.Column(db.Integer)  # 0=Monday, 6=Sunday
    hour_of_day = db.Column(db.Integer)  # 0-23
    crowd_level = db.Column(db.Integer)  # 1-5 scale (1=empty, 5=very crowded)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_image_size(image):
    img = Image.open(io.BytesIO(image.read()))
    image.seek(0)
    return img.size == app.config['GALLERY_IMAGE_SIZE']

def check_if_holiday(date):
    """Check if date is a holiday in India"""
    holidays = [
        '01-26', # Republic Day
        '08-15', # Independence Day
        '10-02', # Gandhi Jayanti
    ]
    return date.strftime('%m-%d') in holidays

@app.context_processor
def inject_current_time():
    now = datetime.now(timezone.utc).astimezone(IST)
    return {
        'current_time': now,
        'is_holiday': check_if_holiday(now)
    }
def get_weather_data(location):
    try:
        response = requests.get(
            "https://api.openweathermap.org/data/2.5/weather",
            params={
                'q': location,
                'appid': app.config['WEATHER_API_KEY'],
                'units': 'metric',
                'lang': 'en'
            },
            timeout=10
        )
        
        if response.status_code != 200:
            app.logger.error(f"Weather API Error: {response.json().get('message')}")
            return None
            
        data = response.json()
        return {
            'temp': data['main']['temp'],
            'description': data['weather'][0]['description'],
            'icon': data['weather'][0]['icon'],
            'humidity': data['main']['humidity'],
            'wind': data['wind']['speed']
        }
    except Exception as e:
        app.logger.error(f"Weather API Exception: {str(e)}")
        return None

def get_nearby_places(location, lat=None, lng=None):
    try:
        if not lat or not lng:
            location_obj = geocode(f"{location}, India", exactly_one=True)
            if not location_obj:
                return []
            lat, lng = location_obj.latitude, location_obj.longitude

        overpass_query = f"""
        [out:json][timeout:25];
        (
          node["tourism"~"attraction|museum|zoo|viewpoint|hot_spring|artwork"](around:50000,{lat},{lng});
          way["tourism"~"."](around:50000,{lat},{lng});
          node["natural"~"peak|waterfall|spring|valley|beach|cliff"](around:50000,{lat},{lng});
          node["amenity"="place_of_worship"](around:50000,{lat},{lng});
          node["leisure"~"park|garden|nature_reserve"](around:50000,{lat},{lng});
          node["historic"~"monument|memorial|fort|ruins"](around:50000,{lat},{lng});
        );
        out center 15;
        (._;>;);
        out skel qt;
        """
        
        response = requests.get(
            "https://overpass-api.de/api/interpreter",
            data={'data': overpass_query},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()

        nearby_places = []
        seen_names = set()

        for element in data.get('elements', []):
            if 'tags' not in element:
                continue
                
            tags = element['tags']
            name = tags.get('name', 'Unnamed Place')
            
            if name in seen_names or name == 'Unnamed Place':
                continue
            seen_names.add(name)
            
            if element['type'] == 'node':
                el_lat, el_lng = element['lat'], element['lon']
            else:
                el_lat, el_lng = element['center']['lat'], element['center']['lon']
            
            distance = geodesic((lat, lng), (el_lat, el_lng)).km
            
            place_type = 'Attraction'
            for key in ['tourism', 'natural', 'amenity', 'leisure', 'historic']:
                if key in tags:
                    place_type = tags[key].replace('_', ' ').title()
                    break
            
            nearby_places.append({
                'name': name,
                'distance': f"{distance:.1f} km",
                'type': place_type,
                'map_url': f"https://www.google.com/maps?q={el_lat},{el_lng}",
                'coordinates': (el_lat, el_lng)
            })
        
        nearby_places.sort(key=lambda x: float(x['distance'].split()[0]))
        return nearby_places[:5]
    except Exception as e:
        app.logger.error(f"Error in get_nearby_places: {str(e)}")
        return []

def predict_crowd(place_id):
    try:
        place = Place.query.get(place_id)
        if not place:
            return {'prediction': 50, 'level': 'Medium'}
        
        model_path = f"crowd_models/place_{place_id}.pkl"
        if not os.path.exists(model_path):
            return initialize_crowd_prediction(place_id)
            
        model = joblib.load(model_path)
        
        now = datetime.now(timezone.utc)
        features = pd.DataFrame([{
            'day_of_week': now.weekday(),
            'hour_of_day': now.hour,
            'month': now.month,
            'is_weekend': 1 if now.weekday() >= 5 else 0,
            'is_holiday': check_if_holiday(now)
        }])
        
        prediction = model.predict(features)[0]
        prediction = max(0, min(100, prediction))
        
        if prediction < 30:
            level = "Low"
        elif prediction < 70:
            level = "Medium"
        else:
            level = "High"
            
        return {
            'prediction': round(prediction),
            'level': level,
            'confidence': "High" if len(place.visit_history) > 50 else "Medium" if len(place.visit_history) > 10 else "Low"
        }
    except Exception as e:
        app.logger.error(f"Crowd prediction error: {str(e)}")
        return {'prediction': 50, 'level': 'Medium', 'confidence': 'Low'}

def initialize_crowd_prediction(place_id):
    return {
        'prediction': 30,
        'level': 'Low',
        'confidence': 'None (New Place)'
    }

def update_crowd_model(place_id, actual_crowd):
    try:
        place = Place.query.get(place_id)
        if not place:
            return False
            
        now = datetime.now(timezone.utc)
        visit = PlaceVisit(
            place_id=place_id,
            visit_date=now,
            day_of_week=now.weekday(),
            hour_of_day=now.hour,
            crowd_level=actual_crowd
        )
        db.session.add(visit)
        db.session.commit()
        
        if len(place.visit_history) % 10 == 0:
            train_crowd_model(place_id)
            
        return True
    except Exception as e:
        app.logger.error(f"Error updating crowd model: {str(e)}")
        return False

def train_crowd_model(place_id):
    try:
        visits = PlaceVisit.query.filter_by(place_id=place_id).all()
        if len(visits) < 10:
            return False
            
        data = []
        for visit in visits:
            data.append({
                'day_of_week': visit.day_of_week,
                'hour_of_day': visit.hour_of_day,
                'month': visit.visit_date.month,
                'is_weekend': 1 if visit.day_of_week >= 5 else 0,
                'crowd_level': visit.crowd_level * 20
            })
            
        df = pd.DataFrame(data)
        X = df[['day_of_week', 'hour_of_day', 'month', 'is_weekend']]
        y = df['crowd_level']
        
        model = RandomForestRegressor(n_estimators=50)
        model.fit(X, y)
        
        joblib.dump(model, f"crowd_models/place_{place_id}.pkl")
        return True
    except Exception as e:
        app.logger.error(f"Error training model: {str(e)}")
        return False
    
# @app.route('/')
# def home():
#     places = Place.query.order_by(Place.timestamp.desc()).all()
#     return render_template("home.html", places=places)

@app.route('/place/<int:place_id>')
def place_details(place_id):
    place = Place.query.get_or_404(place_id)
    weather_data = get_weather_data(place.location)
    nearby_places = get_nearby_places(place.location, place.lat, place.lng)
    crowd_prediction = predict_crowd(place.id)
    
    return render_template("place_details.html", 
                         place=place,
                         weather=weather_data,
                         nearby_places=nearby_places,
                         crowd_prediction=crowd_prediction)

@app.route('/place/<int:place_id>/crowd_feedback', methods=['POST'])
def crowd_feedback(place_id):
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'error': 'Login required'})
    
    try:
        crowd_level = int(request.json.get('crowd_level', 3))
        if update_crowd_model(place_id, crowd_level):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Update failed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Template filter 
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%b %d, %Y %I:%M %p'):
    if value.tzinfo is None:
        value = pytz.utc.localize(value)
    return value.astimezone(IST).strftime(format)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The form submission was invalid. Please try again.', 'danger')
    return redirect(request.referrer or url_for('home'))

# Admin Routes 
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        try:
            if not request.form.get('csrf_token'):
                flash("Invalid form submission", "danger")
                return redirect(url_for('admin_login'))
            
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')

            if not email or not password:
                flash("Email and password are required", "danger")
                return redirect(url_for('admin_login'))

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
        
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash("An error occurred during login", "danger")

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

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    if user.is_permanent_admin:
        flash("Cannot delete permanent admin", "danger")
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Delete user's places first
        Place.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")
    
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
            if not (file and allowed_file(file.filename)):
                flash('Invalid image format', 'danger')
                return redirect(request.url)
            
            if not allowed_file(file.filename):  # Only checks extension now
                flash('Allowed formats: PNG, JPG, JPEG, GIF, WEBP', 'danger')
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
            
            # Geocode the location
            location = geocode(f"{request.form['location']}, India", exactly_one=True)
            
            new_place = Place(
                name=request.form.get('name'),
                location=request.form.get('location'),
                description=request.form.get('description'),
                best_time=request.form.get('best_time'),
                image=filename,
                user_id=session['user_id'],
                lat=location.latitude if location else None,
                lng=location.longitude if location else None
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
                if file and allowed_file(file.filename):
                    if validate_image_size(file):
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