from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from app import app, db
from models import Code
from auth import admin_required
import re
import os
import jwt
import uuid
import secrets
import string
import hashlib
import logging
from functools import wraps
from sqlalchemy import text, Index
import time

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-string')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Rate limiting configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

db = SQLAlchemy(app)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    storage_uri=REDIS_URL,
    default_limits=["1000 per hour"]
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# User Model (simplified according to suggested schema)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    @property
    def is_subscribed(self):
        """Check if user has an active subscription"""
        active_subscription = Subscription.query.filter_by(
            user_id=self.id
        ).filter(Subscription.expires_at > datetime.utcnow()).first()
        return active_subscription is not None
    
    @property
    def subscription_expires_at(self):
        """Get the expiration date of the user's active subscription"""
        active_subscription = Subscription.query.filter_by(
            user_id=self.id
        ).filter(Subscription.expires_at > datetime.utcnow()).first()
        return active_subscription.expires_at if active_subscription else None

# RedeemCard Model (renamed and simplified according to suggested schema)
class RedeemCard(db.Model):
    __tablename__ = 'redeem_cards'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    redeemed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Indexes according to specification
    __table_args__ = (
        Index('idx_code_unique', 'code', unique=True),  # Unique index on code
        Index('idx_redeemed_by', 'redeemed_by'),  # For user redemption history
        Index('idx_is_used', 'is_used'),  # For filtering unused codes
    )
    
    def __repr__(self):
        return f'<RedeemCard {self.code}>'

# Subscription Model (separate table as suggested)
class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Indexes according to specification
    __table_args__ = (
        Index('idx_user_id', 'user_id'),  # Index on user_id as specified
        Index('idx_expires_at', 'expires_at'),  # For subscription queries
        Index('idx_user_expires', 'user_id', 'expires_at'),  # Composite for active subscriptions
    )
    
    def __repr__(self):
        return f'<Subscription user_id={self.user_id} expires_at={self.expires_at}>'

# Validation functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Valid password"

# Enhanced Code Generation Functions for Security
def generate_secure_code():
    """Generate a cryptographically secure, unique redeem code"""
    # Use multiple sources of entropy for maximum security
    timestamp = str(int(time.time() * 1000000))  # Microsecond precision
    random_bytes = secrets.token_bytes(16)  # 128 bits of entropy
    uuid_part = str(uuid.uuid4()).replace('-', '')
    
    # Combine entropy sources
    combined = f"{timestamp}{random_bytes.hex()}{uuid_part}"
    
    # Create hash for additional randomness
    hash_obj = hashlib.sha256(combined.encode())
    hash_hex = hash_obj.hexdigest().upper()
    
    # Format as readable code with checksum
    code_part1 = hash_hex[:12]
    code_part2 = hash_hex[12:20]
    checksum = hash_hex[-8:]
    
    code = f"{code_part1}-{code_part2}-{checksum}"
    
    # Log generation for security monitoring
    logger.info(f"Generated secure code: {code[:8]}...")
    
    return code

def generate_code_hash(code):
    """Generate a hash of the code for faster database lookups"""
    return hashlib.sha256(code.encode()).hexdigest()

def generate_unique_codes(count):
    """Generate a specified number of unique codes with optimized database checks"""
    codes = []
    attempts = 0
    max_attempts = count * 10  # Prevent infinite loops
    
    # Batch check for existing codes to improve performance
    batch_size = 1000
    existing_codes = set()
    
    # Pre-load existing codes in batches
    offset = 0
    while True:
        batch_codes = RedeemCard.query.with_entities(RedeemCard.code).offset(offset).limit(batch_size).all()
        if not batch_codes:
            break
        existing_codes.update(code_tuple[0] for code_tuple in batch_codes)
        offset += batch_size
    
    logger.info(f"Loaded {len(existing_codes)} existing codes for uniqueness check")
    
    while len(codes) < count and attempts < max_attempts:
        new_code = generate_secure_code()
        
        # Check uniqueness using string comparison (simplified for new schema)
        if new_code not in existing_codes and new_code not in codes:
            codes.append(new_code)
        
        attempts += 1
        
        # Log progress for large batches
        if len(codes) % 10000 == 0 and len(codes) > 0:
            logger.info(f"Generated {len(codes)}/{count} unique codes")
    
    if len(codes) < count:
        raise Exception(f"Could not generate {count} unique codes after {max_attempts} attempts")
    
    logger.info(f"Successfully generated {len(codes)} unique codes")
    return codes

# Subscription Helper Functions
def extend_user_subscription(user_id, months=1):
    """Extend user subscription by specified number of months"""
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"
    
    current_time = datetime.utcnow()
    
    # Check if user has an active subscription
    active_subscription = Subscription.query.filter_by(
        user_id=user_id
    ).filter(Subscription.expires_at > current_time).first()
    
    if active_subscription:
        # Extend existing subscription
        new_expiry = active_subscription.expires_at + timedelta(days=30 * months)
        active_subscription.expires_at = new_expiry
    else:
        # Create new subscription
        new_expiry = current_time + timedelta(days=30 * months)
        new_subscription = Subscription(
            user_id=user_id,
            expires_at=new_expiry
        )
        db.session.add(new_subscription)
    
    db.session.commit()
    
    return True, new_expiry

def redeem_code_atomic(code, user_id):
    """
    Atomically redeem a code with race condition prevention.
    Uses database-level locking for performance and security.
    """
    try:
        start_time = time.time()
        
        # Start a transaction with row-level locking
        with db.session.begin_nested():
            # Find unused redeem card with the code
            redeem_card = db.session.query(RedeemCard).filter_by(
                code=code, 
                is_used=False
            ).with_for_update().first()
            
            if not redeem_card:
                # Log failed attempt for security monitoring
                logger.warning(f"Invalid redemption attempt for code: {code[:8]}... by user {user_id}")
                return False, "Invalid redeem code"
            
            # Check if code has expired
            if redeem_card.expires_at and redeem_card.expires_at < datetime.utcnow():
                logger.warning(f"Expired code redemption attempt: {code[:8]}... by user {user_id}")
                return False, "Redeem code has expired"
            
            # Verify user exists
            user = User.query.get(user_id)
            if not user:
                return False, "User not found"
            
            # Mark code as used
            redeem_card.is_used = True
            redeem_card.redeemed_by = user_id
            
            # Extend user subscription
            success, new_expiry = extend_user_subscription(user_id, 1)
            if not success:
                # Rollback if subscription extension fails
                db.session.rollback()
                return False, new_expiry
            
            # Commit the transaction
            db.session.commit()
            
            # Log successful redemption
            processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            logger.info(f"Code redeemed successfully: {code[:8]}... by user {user_id} in {processing_time:.2f}ms")
            
            return True, {
                'user_id': user_id,
                'code': code,
                'new_subscription_expiry': new_expiry.isoformat(),
                'redeemed_at': datetime.utcnow().isoformat(),
                'processing_time_ms': processing_time
            }
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error during redemption: {str(e)}")
        return False, f"Database error: {str(e)}"

# JWT Helper Functions
def generate_jwt_token(user_id, email):
    """Generate JWT token for user"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token

def token_required(f):
    """Decorator to require JWT token for protected routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin privileges for protected routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
            
            if not current_user.is_admin:
                return jsonify({'error': 'Admin privileges required'}), 403
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# API Routes
@app.route('/api/register', methods=['POST'])
def register_user():
    """Register a new user with email and password"""
    try:
        data = request.get_json()
        
        # Check if data is provided
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        # Validate required fields
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password strength
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            return jsonify({'error': password_message}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User with this email already exists'}), 409
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate JWT token
        token = generate_jwt_token(new_user.id, new_user.email)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'created_at': new_user.created_at.isoformat()
            },
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
def login_user():
    """Login user with email and password"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate JWT token
        token = generate_jwt_token(user.id, user.email)
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'created_at': user.created_at.isoformat()
            },
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    """Get current user profile (protected route)"""
    return jsonify({
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'created_at': current_user.created_at.isoformat()
        }
    }), 200

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    """Get all users (for testing purposes) - Protected route"""
    try:
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'email': user.email,
                'created_at': user.created_at.isoformat()
            })
        return jsonify({'users': user_list}), 200
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/generate-codes', methods=['POST'])
@admin_required
@limiter.limit("5 per minute")  # Rate limit code generation
def generate_redeem_codes(current_user):
    """Generate redeem codes (Admin only)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        count = data.get('count')
        
        if not count:
            return jsonify({'error': 'Count is required'}), 400
        
        if not isinstance(count, int) or count <= 0:
            return jsonify({'error': 'Count must be a positive integer'}), 400
        
        if count > 10000:  # Reasonable limit to prevent abuse
            return jsonify({'error': 'Count cannot exceed 10,000 codes per request'}), 400
        
        # Generate unique codes
        try:
            codes = generate_unique_codes(count)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
        # Store codes in database with batch optimization
        redeem_cards = []
        for code in codes:
            redeem_card = RedeemCard(
                code=code,
                is_used=False
                # Note: expires_at can be set later if needed
            )
            db.session.add(redeem_card)
            redeem_cards.append(redeem_card)
            
            # Batch commit for large numbers to avoid memory issues
            if len(redeem_cards) % 10000 == 0:
                db.session.commit()
                logger.info(f"Batch committed {len(redeem_cards)} codes")
        
        db.session.commit()
        
        # Return the generated codes
        code_list = [card.code for card in redeem_cards]
        
        return jsonify({
            'message': f'Successfully generated {len(code_list)} redeem codes',
            'count': len(code_list),
            'codes': code_list
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/codes', methods=['GET'])
@admin_required
def get_redeem_codes(current_user):
    """Get all redeem codes (Admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        used_filter = request.args.get('used', type=str)
        
        query = RedeemCard.query
        
        if used_filter == 'true':
            query = query.filter_by(is_used=True)
        elif used_filter == 'false':
            query = query.filter_by(is_used=False)
        
        codes = query.order_by(RedeemCard.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        code_list = []
        for code in codes.items:
            code_data = {
                'id': code.id,
                'code': code.code,
                'is_used': code.is_used,
                'created_at': code.created_at.isoformat(),
                'expires_at': code.expires_at.isoformat() if code.expires_at else None
            }
            
            if code.is_used:
                code_data['redeemed_by'] = code.redeemed_by
                code_data['redeemed_at'] = code.created_at.isoformat()  # When it was marked as used
            
            code_list.append(code_data)
        
        return jsonify({
            'codes': code_list,
            'total': codes.total,
            'pages': codes.pages,
            'current_page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/redeem', methods=['POST'])
@token_required
@limiter.limit("10 per minute")  # Rate limit redemption attempts
def redeem_code(current_user):
    """Redeem a code to extend user subscription (authenticated users only)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = data.get('user_id')
        card_code = data.get('card_code')
        
        # Validate required fields
        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400
        
        if not card_code:
            return jsonify({'error': 'card_code is required'}), 400
        
        # Validate user_id is integer
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'user_id must be a valid integer'}), 400
        
        # Security check: Users can only redeem codes for themselves
        if current_user.id != user_id:
            return jsonify({'error': 'You can only redeem codes for your own account'}), 403
        
        # Validate card_code format (basic security check)
        if not isinstance(card_code, str) or len(card_code) < 10:
            return jsonify({'error': 'Invalid card_code format'}), 400
        
        # Sanitize card_code (remove any potential injection attempts)
        card_code = card_code.strip().upper()
        if not re.match(r'^[A-Z0-9\-]+$', card_code):
            return jsonify({'error': 'Invalid card_code format'}), 400
        
        # Attempt to redeem the code atomically
        success, result = redeem_code_atomic(card_code, user_id)
        
        if success:
            return jsonify({
                'message': 'Code redeemed successfully',
                'subscription_extended': True,
                'new_subscription_expiry': result['new_subscription_expiry'],
                'redeemed_at': result['redeemed_at']
            }), 200
        else:
            # Determine appropriate error code
            if "already been used" in result:
                return jsonify({'error': result}), 409  # Conflict
            elif "Invalid redeem code" in result:
                return jsonify({'error': result}), 404  # Not Found
            elif "User not found" in result:
                return jsonify({'error': result}), 404  # Not Found
            else:
                return jsonify({'error': result}), 400  # Bad Request
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/subscription', methods=['GET'])
@token_required
def get_user_subscription(current_user):
    """Get current user's subscription status"""
    return jsonify({
        'user_id': current_user.id,
        'email': current_user.email,
        'is_subscribed': current_user.is_subscribed,
        'subscription_expires_at': current_user.subscription_expires_at.isoformat() if current_user.subscription_expires_at else None
    }), 200

@app.route('/subscription/<int:user_id>', methods=['GET'])
@token_required
def get_subscription_by_user_id(current_user, user_id):
    """Get subscription status for any user by user_id"""
    try:
        # Find the target user
        target_user = User.query.get(user_id)
        
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        # Security check: Users can only check their own subscription unless they're admin
        if current_user.id != user_id and not current_user.is_admin:
            return jsonify({'error': 'Access denied. You can only check your own subscription status'}), 403
        
        # Calculate subscription status using the new schema
        current_time = datetime.utcnow()
        active_subscription = Subscription.query.filter_by(
            user_id=user_id
        ).filter(Subscription.expires_at > current_time).first()
        
        is_subscribed = active_subscription is not None
        subscription_status = "active" if is_subscribed else "inactive"
        subscription_expires_at = active_subscription.expires_at if active_subscription else None
        
        response_data = {
            'user_id': target_user.id,
            'email': target_user.email,
            'is_subscribed': is_subscribed,
            'subscription_status': subscription_status,
            'subscription_expires_at': subscription_expires_at.isoformat() if subscription_expires_at else None,
            'days_remaining': None,
            'created_at': target_user.created_at.isoformat()
        }
        
        # Calculate days remaining if subscription is active
        if is_subscribed and subscription_expires_at:
            days_remaining = (subscription_expires_at - current_time).days
            response_data['days_remaining'] = max(0, days_remaining)
        
        return jsonify(response_data), 200
        
    except ValueError:
        return jsonify({'error': 'Invalid user_id format'}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'User Registration API is running'}), 200

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'AdminPassword123')
    
    admin_user = User.query.filter_by(email=admin_email).first()
    if not admin_user:
        admin_user = User(
            email=admin_email,
            password_hash=generate_password_hash(admin_password),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user created: {admin_email}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)

@app.route('/admin/codes', methods=['GET'])
@admin_required
def admin_list_codes():
    """
    Endpoint to list all codes with pagination.
    Accessible only by admin users.
    """
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 100))

    codes_paginated = Code.query.order_by(Code.created_at.desc()).paginate(page, per_page, False)

    codes = [{
        "code": c.code,
        "status": c.status,
        "redeemed_by": c.redeemed_by,
        "redeemed_at": c.redeemed_at.isoformat() if c.redeemed_at else None
    } for c in codes_paginated.items]

    return jsonify({
        "page": page,
        "per_page": per_page,
        "total": codes_paginated.total,
        "codes": codes
    })
