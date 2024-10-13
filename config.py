import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')  # Replace with a strong secret key
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')  # Secret key for JWT
    MONGODB_SETTINGS = {
        'db': os.getenv('MONGO_DB', 'your_db_name'),  # Name of your MongoDB database
        'host': os.getenv('MONGO_URI', 'mongodb://localhost:27017/your_db_name'),  # MongoDB URI
    }
