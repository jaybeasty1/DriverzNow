
import os
import pyotp
import json
import logging
import stripe
import googlemaps
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt_identity, jwt_required
from flask_mail import Mail, Message
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from mongoengine import connect, Document, StringField, DateTimeField, ListField, ReferenceField
from mongoengine.errors import NotUniqueError
from authlib.integrations.flask_client import OAuth
from flask_babel import Babel
from sentry_sdk import init as sentry_init
from sentry_sdk.integrations.flask import FlaskIntegration
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.config.from_object(os.getenv('APP_SETTINGS', 'config.Config'))

# Connect to MongoDB
connect(db='driverz_app', host='mongodb://localhost:27017/driverz_app')

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
socketio = SocketIO(app)
oauth = OAuth(app)
babel = Babel(app)

# Stripe setup
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Google Maps API setup with a dummy key
gmaps = googlemaps.Client(key='YOUR_DUMMY_GOOGLE_MAPS_API_KEY')

# Sentry error tracking
sentry_init(dsn=os.getenv('SENTRY_DSN'), integrations=[FlaskIntegration()], traces_sample_rate=1.0)

# Rate limiting setup
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Email confirmation and password reset setup
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OAuth configuration for Google login
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'}
)

# MongoDB Models
class User(Document):
    name = StringField(required=True)
    email = StringField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(required=True, choices=['rider', 'driver', 'admin'])
    rides = ListField(ReferenceField('Ride'))
    created_at = DateTimeField(default=datetime.utcnow)
    is_verified = StringField(default='False')
    otp_secret = StringField()
    is_available = StringField(default='True')
    vehicles = ListField(ReferenceField('Vehicle'))
    phone_number = StringField()  # New field for phone number
    address = StringField()        # New field for address
    payment_info = StringField()   # New field for payment information
    profile_picture = StringField() # New field for profile picture URL

class Ride(Document):
    rider_id = ReferenceField(User, reverse_delete_rule=4)
    driver_id = ReferenceField(User, reverse_delete_rule=4, null=True)
    pickup_location = StringField(required=True)
    destination = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    status = StringField(default='pending', choices=['pending', 'accepted', 'in-progress', 'completed', 'canceled'])
    rating = StringField(default='')
    review = StringField(default='')
    scheduled_time = DateTimeField()  # New field for scheduled rides
    comments = ListField(StringField())  # List of comments for reviews

class Vehicle(Document):
    make = StringField(required=True)
    model = StringField(required=True)
    year = StringField(required=True)
    license_plate = StringField(required=True, unique=True)
    driver = ReferenceField(User, reverse_delete_rule=4)

class ActivityLog(Document):
    user = ReferenceField(User)
    action = StringField(required=True)
    timestamp = DateTimeField(default=datetime.utcnow)

# Middleware for logging requests and responses
@app.before_request
def log_request_info():
    logger.info(f"Request: {request.method} {request.url} | Body: {request.get_json() or request.form}")

@app.after_request
def log_response_info(response):
    logger.info(f"Response: {response.status} | Body: {response.get_data(as_text=True)}")
    return response

# Decorators for role-based access control
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = User.objects.get(id=get_jwt_identity())
        if current_user.role != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = User.objects.get(id=get_jwt_identity())
            if current_user.role != role:
                return jsonify({"error": f"{role.capitalize()} access required"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# User signup route
@app.route('/signup', methods=['POST'])
@limiter.limit("10 per hour")
def signup():
    data = request.form
    if 'email' not in data or 'password' not in data or 'role' not in data or 'name' not in data:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        if len(data['password']) < 8 or not any(char.isdigit() for char in data['password']):
            return jsonify({"error": "Password must be at least 8 characters and contain a number"}), 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            name=data['name'],
            email=data['email'],
            password=hashed_password,
            role=data['role']
        )
        user.otp_secret = pyotp.random_base32()
        user.save()

        token = s.dumps(data['email'], salt='email-confirm')
        verification_url = url_for('confirm_email', token=token, _external=True)
        msg = Message('Email Verification', sender=os.getenv('MAIL_USERNAME'), recipients=[data['email']])
        msg.body = f'Please verify your email: {verification_url}'
        mail.send(msg)

        return jsonify({"message": "Check your email to verify your account."}), 201
    except NotUniqueError:
        return jsonify({"error": "Email already exists"}), 400
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({"error": "An error occurred while signing up."}), 500

# Email confirmation route
@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.objects.get(email=email)
        user.is_verified = 'True'
        user.save()
        return jsonify({"message": "Email verified successfully"}), 200
    except Exception as e:
        logger.error(f"Email confirmation error: {str(e)}")
        return jsonify({"error": "The confirmation link is invalid or has expired"}), 400

# Login route with 2FA
@app.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    data = request.form
    try:
        user = User.objects.get(email=data['email'])
        if bcrypt.check_password_hash(user.password, data['password']):
            if pyotp.TOTP(user.otp_secret).verify(data['otp']):
                access_token = create_access_token(identity=str(user.id))
                refresh_token = create_refresh_token(identity=str(user.id))
                return jsonify(access_token=access_token, refresh_token=refresh_token), 200
            return jsonify({"error": "Invalid OTP"}), 400
        return jsonify({"error": "Invalid credentials"}), 400
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Invalid credentials"}), 400

# User profile route
@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    current_user = User.objects.get(id=get_jwt_identity())
    if request.method == 'GET':
        return jsonify({
            "name": current_user.name,
            "email": current_user.email,
            "role": current_user.role,
            "phone_number": current_user.phone_number,
            "address": current_user.address,
            "payment_info": current_user.payment_info,
            "profile_picture": current_user.profile_picture
        }), 200

    if request.method == 'PUT':
        data = request.form
        if 'phone_number' in data:
            current_user.phone_number = data['phone_number']
        if 'address' in data:
            current_user.address = data['address']
        if 'payment_info' in data:
            current_user.payment_info = data['payment_info']
        if 'profile_picture' in data:
            current_user.profile_picture = data['profile_picture']  # Assume it's a URL

        current_user.save()
        return jsonify({"message": "Profile updated successfully."}), 200

# Ride creation route
@app.route('/rides', methods=['POST'])
@jwt_required()
def create_ride():
    current_user = User.objects.get(id=get_jwt_identity())
    data = request.form
    ride = Ride(
        rider_id=current_user,
        pickup_location=data['pickup_location'],
        destination=data['destination'],
        scheduled_time=datetime.strptime(data['scheduled_time'], '%Y-%m-%d %H:%M:%S') if 'scheduled_time' in data else None
    )
    ride.save()
    current_user.rides.append(ride)
    current_user.save()
    return jsonify({"message": "Ride created successfully."}), 201

# View rides route
@app.route('/rides', methods=['GET'])
@jwt_required()
def view_rides():
    current_user = User.objects.get(id=get_jwt_identity())
    rides = Ride.objects(rider_id=current_user.id)
    return jsonify([{
        "pickup_location": ride.pickup_location,
        "destination": ride.destination,
        "status": ride.status,
        "scheduled_time": ride.scheduled_time,
        "rating": ride.rating,
        "review": ride.review
    } for ride in rides]), 200

# Cancel ride route
@app.route('/rides/<ride_id>', methods=['DELETE'])
@jwt_required()
def cancel_ride(ride_id):
    current_user = User.objects.get(id=get_jwt_identity())
    try:
        ride = Ride.objects.get(id=ride_id, rider_id=current_user.id)
        ride.status = 'canceled'
        ride.save()
        return jsonify({"message": "Ride canceled successfully."}), 200
    except Ride.DoesNotExist:
        return jsonify({"error": "Ride not found."}), 404

# Accept ride route for drivers
@app.route('/rides/accept/<ride_id>', methods=['POST'])
@jwt_required()
@role_required('driver')
def accept_ride(ride_id):
    current_user = User.objects.get(id=get_jwt_identity())
    try:
        ride = Ride.objects.get(id=ride_id, status='pending')
        ride.driver_id = current_user
        ride.status = 'accepted'
        ride.save()
        return jsonify({"message": "Ride accepted successfully."}), 200
    except Ride.DoesNotExist:
        return jsonify({"error": "Ride not found."}), 404

# Submit review route
@app.route('/rides/review/<ride_id>', methods=['POST'])
@jwt_required()
def submit_review(ride_id):
    current_user = User.objects.get(id=get_jwt_identity())
    data = request.form
    try:
        ride = Ride.objects.get(id=ride_id, rider_id=current_user.id)
        ride.rating = data['rating']
        ride.review = data['review']
        ride.save()
        return jsonify({"message": "Review submitted successfully."}), 200
    except Ride.DoesNotExist:
        return jsonify({"error": "Ride not found."}), 404

# Admin dashboard route
@app.route('/admin/dashboard', methods=['GET'])
@jwt_required()
@admin_required
def admin_dashboard():
    users_count = User.objects.count()
    rides_count = Ride.objects.count()
    return jsonify({
        "total_users": users_count,
        "total_rides": rides_count,
        "total_drivers": User.objects.filter(role='driver').count(),
        "total_riders": User.objects.filter(role='rider').count()
    }), 200

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)
