#!/usr/bin/env python3
"""
Trontiq Authentication Server
Simple Flask server for handling secure authentication cookies
Deployable to Render for maintaining authentication state across browser tabs
"""

import os
import json
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import redis
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Enable CORS for browser extension
CORS(app, origins=['chrome-extension://*', 'moz-extension://*'], supports_credentials=True)

# Redis configuration for session storage
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
redis_client = None

try:
    redis_client = redis.from_url(REDIS_URL)
    redis_client.ping()  # Test connection
except Exception as e:
    print(f"Redis connection failed: {e}")
    redis_client = None

# Cookie configuration
COOKIE_NAME = 'trontiq_auth'
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'true').lower() == 'true'
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = 'Lax'
COOKIE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days in seconds

def generate_session_token(user_id, email):
    """Generate a secure session token"""
    timestamp = str(int(time.time()))
    random_component = secrets.token_hex(16)
    data_to_hash = f"{user_id}:{email}:{timestamp}:{random_component}"
    hash_value = hashlib.sha256(data_to_hash.encode()).hexdigest()
    return f"{timestamp}.{random_component}.{hash_value}"

def validate_session_token(token):
    """Validate a session token"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        timestamp, random_component, hash_value = parts
        timestamp_int = int(timestamp)
        
        # Check if token is expired (older than 7 days)
        if time.time() - timestamp_int > COOKIE_MAX_AGE:
            return None
            
        return timestamp_int
    except (ValueError, IndexError):
        return None

def store_session(user_id, email, token):
    """Store session in Redis or fallback to memory"""
    session_data = {
        'user_id': user_id,
        'email': email,
        'created_at': time.time(),
        'last_activity': time.time()
    }
    
    if redis_client:
        try:
            redis_client.setex(f"session:{token}", COOKIE_MAX_AGE, json.dumps(session_data))
            return True
        except Exception as e:
            print(f"Redis storage failed: {e}")
    
    # Fallback to in-memory storage (not recommended for production)
    if not hasattr(app, 'session_store'):
        app.session_store = {}
    
    app.session_store[token] = session_data
    return True

def get_session(token):
    """Retrieve session data"""
    if redis_client:
        try:
            session_data = redis_client.get(f"session:{token}")
            if session_data:
                data = json.loads(session_data)
                # Update last activity
                data['last_activity'] = time.time()
                redis_client.setex(f"session:{token}", COOKIE_MAX_AGE, json.dumps(data))
                return data
        except Exception as e:
            print(f"Redis retrieval failed: {e}")
    
    # Fallback to in-memory storage
    if hasattr(app, 'session_store') and token in app.session_store:
        session_data = app.session_store[token]
        session_data['last_activity'] = time.time()
        return session_data
    
    return None

def invalidate_session(token):
    """Invalidate a session"""
    if redis_client:
        try:
            redis_client.delete(f"session:{token}")
        except Exception as e:
            print(f"Redis deletion failed: {e}")
    
    # Fallback to in-memory storage
    if hasattr(app, 'session_store') and token in app.session_store:
        del app.session_store[token]

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'redis_connected': redis_client is not None
    })

@app.route('/auth/login', methods=['POST'])
def login():
    """Handle user login and set authentication cookie"""
    try:
        data = request.get_json()
        if not data or 'user_id' not in data or 'email' not in data:
            return jsonify({'error': 'Missing user_id or email'}), 400
        
        user_id = data['user_id']
        email = data['email']
        
        # Generate secure session token
        session_token = generate_session_token(user_id, email)
        
        # Store session
        if store_session(user_id, email, session_token):
            # Create response with cookie
            response = make_response(jsonify({
                'success': True,
                'message': 'Login successful',
                'user_id': user_id,
                'email': email
            }))
            
            # Set secure cookie
            response.set_cookie(
                COOKIE_NAME,
                session_token,
                max_age=COOKIE_MAX_AGE,
                secure=COOKIE_SECURE,
                httponly=COOKIE_HTTPONLY,
                samesite=COOKIE_SAMESITE
            )
            
            return response, 200
        else:
            return jsonify({'error': 'Failed to create session'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/auth/validate', methods=['GET'])
def validate_auth():
    """Validate authentication cookie and return user info"""
    try:
        # Get cookie from request
        auth_cookie = request.cookies.get(COOKIE_NAME)
        if not auth_cookie:
            return jsonify({'authenticated': False, 'error': 'No authentication cookie'}), 401
        
        # Validate token format
        timestamp = validate_session_token(auth_cookie)
        if timestamp is None:
            return jsonify({'authenticated': False, 'error': 'Invalid or expired token'}), 401
        
        # Get session data
        session_data = get_session(auth_cookie)
        if not session_data:
            return jsonify({'authenticated': False, 'error': 'Session not found'}), 401
        
        return jsonify({
            'authenticated': True,
            'user_id': session_data['user_id'],
            'email': session_data['email'],
            'created_at': session_data['created_at'],
            'last_activity': session_data['last_activity']
        }), 200
        
    except Exception as e:
        return jsonify({'authenticated': False, 'error': f'Validation failed: {str(e)}'}), 500

@app.route('/auth/logout', methods=['POST'])
def logout():
    """Handle user logout and invalidate cookie"""
    try:
        auth_cookie = request.cookies.get(COOKIE_NAME)
        if auth_cookie:
            invalidate_session(auth_cookie)
        
        # Create response that clears the cookie
        response = make_response(jsonify({
            'success': True,
            'message': 'Logout successful'
        }))
        
        # Clear the cookie
        response.set_cookie(
            COOKIE_NAME,
            '',
            max_age=0,
            expires=0,
            secure=COOKIE_SECURE,
            httponly=COOKIE_HTTPONLY,
            samesite=COOKIE_SAMESITE
        )
        
        return response, 200
        
    except Exception as e:
        return jsonify({'error': f'Logout failed: {str(e)}'}), 500

@app.route('/auth/refresh', methods=['POST'])
def refresh_session():
    """Refresh session activity timestamp"""
    try:
        auth_cookie = request.cookies.get(COOKIE_NAME)
        if not auth_cookie:
            return jsonify({'error': 'No authentication cookie'}), 401
        
        session_data = get_session(auth_cookie)
        if not session_data:
            return jsonify({'error': 'Session not found'}), 401
        
        # Session is automatically refreshed in get_session()
        return jsonify({
            'success': True,
            'message': 'Session refreshed',
            'last_activity': session_data['last_activity']
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {str(e)}'}), 500

@app.route('/', methods=['GET'])
def root():
    """Root endpoint with basic info"""
    return jsonify({
        'service': 'Trontiq Authentication Server',
        'version': '1.0.0',
        'endpoints': {
            'health': '/health',
            'login': '/auth/login',
            'validate': '/auth/validate',
            'logout': '/auth/logout',
            'refresh': '/auth/refresh'
        },
        'status': 'running'
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    print(f"Starting Trontiq Auth Server on port {port}")
    print(f"Debug mode: {debug}")
    print(f"Redis connected: {redis_client is not None}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
