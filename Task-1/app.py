# python -m venv venv
# cd venv/scripts
# .\activate
# pip install flask pyotp qrcode pillow mysql-connector-python flask-jwt-extended

from flask import Flask, request, jsonify, send_file
import pyotp
import qrcode
import io
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'
jwt = JWTManager(app)

# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="flask_auth"
)
cursor = db.cursor()

# Mock storage for 2FA secrets (in production, store in the database)
user_secrets = {}

# Create Users and Products tables if they don't exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(256) NOT NULL,
        secret_key VARCHAR(256)
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS Products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description VARCHAR(255),
        price DECIMAL(10, 2) NOT NULL,
        quantity INT NOT NULL
    )
""")
db.commit()

# User Registration
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    # Check if user already exists
    cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
    if cursor.fetchone():
        return jsonify({'message': 'User already exists'}), 400

    # Hash password and generate 2FA secret
    hashed_password = generate_password_hash(password)
    secret = pyotp.random_base32()

    # Store user in the database
    cursor.execute("INSERT INTO Users (username, password, secret_key) VALUES (%s, %s, %s)",
                   (username, hashed_password, secret))
    db.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Retrieve user from database
    cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user or not check_password_hash(user[2], password):
        return jsonify({'message': 'Invalid username or password'}), 401

    # Generate QR code for 2FA setup
    uri = pyotp.totp.TOTP(user[3]).provisioning_uri(name=username, issuer_name='Flask_2FA_App')
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img)
    img.seek(0)

    return send_file(img, mimetype='image/png')

# Verify 2FA Code
@app.route('/verify-2fa/<username>', methods=['POST'])
def verify_2fa(username):
    user_code = request.json.get('code')
    cursor.execute("SELECT secret_key FROM Users WHERE username = %s", (username,))
    secret = cursor.fetchone()
    if not secret:
        return jsonify({'message': 'User not found or 2FA not set up'}), 404

    secret = secret[0]
    totp = pyotp.TOTP(secret)
    if totp.verify(user_code):
        # Generate JWT token
        token = create_access_token(identity=username, expires_delta=datetime.timedelta(minutes=10))
        return jsonify({'message': '2FA verified successfully', 'token': token})
    else:
        return jsonify({'message': 'Invalid or expired code'}), 401

# JWT-Secured CRUD Operations for Products
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    username = get_jwt_identity()
    data = request.json
    cursor.execute("INSERT INTO Products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                   (data['name'], data['description'], data['price'], data['quantity']))
    db.commit()
    return jsonify({'message': 'Product created successfully'}), 201

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    cursor.execute("SELECT * FROM Products")
    products = cursor.fetchall()
    return jsonify({'products': products})

@app.route('/products/<int:id>', methods=['PUT'])
@jwt_required()
def update_product(id):
    data = request.json
    cursor.execute("UPDATE Products SET name = %s, description = %s, price = %s, quantity = %s WHERE id = %s",
                   (data['name'], data['description'], data['price'], data['quantity'], id))
    db.commit()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/products/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_product(id):
    cursor.execute("DELETE FROM Products WHERE id = %s", (id,))
    db.commit()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
