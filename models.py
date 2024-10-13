
from mongoengine import Document, StringField, ReferenceField, ListField, DateTimeField, connect
from datetime import datetime

# Connect to MongoDB using settings from the config
connect(db='driverz_app', host='mongodb://localhost:27017/driverz_app')

class User(Document):
    name = StringField(required=True)  # Name of the user
    email = StringField(required=True, unique=True)  # Unique email for each user
    password = StringField(required=True)  # Hashed password for authentication
    role = StringField(required=True, choices=['rider', 'driver'])  # Role can be either 'rider' or 'driver'
    rides = ListField(ReferenceField('Ride'))  # List of rides associated with the user
    created_at = DateTimeField(default=datetime.utcnow)  # Timestamp when the user was created

class Ride(Document):
    rider_id = ReferenceField(User, reverse_delete_rule=4)  # Reference to the rider (User), with delete rules
    driver_id = ReferenceField(User, reverse_delete_rule=4, null=True)  # Reference to the driver (User), can be null initially
    pickup_location = StringField(required=True)  # The location where the ride is requested
    destination = StringField(required=True)  # The destination of the ride
    created_at = DateTimeField(default=datetime.utcnow)  # Timestamp when the ride was created
    status = StringField(default='pending', choices=['pending', 'accepted', 'in-progress', 'completed', 'canceled'])  # Current status of the ride

class Vehicle(Document):
    make = StringField(required=True)  # Make of the vehicle (e.g., Toyota)
    model = StringField(required=True)  # Model of the vehicle (e.g., Camry)
    year = StringField(required=True)  # Year of the vehicle
    license_plate = StringField(required=True, unique=True)  # Unique license plate number
    driver = ReferenceField(User, reverse_delete_rule=4)  # Reference to the driver (User) associated with the vehicle

# Optional: You can add additional methods to User, Ride, or Vehicle classes for functionality
