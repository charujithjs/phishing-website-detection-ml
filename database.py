import mysql.connector
from mysql.connector import Error
from config import DB_CONFIG
import logging
import hmac
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_connection():
    """Create and return a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        logger.error(f"Error connecting to MySQL database: {e}")
        return None

def initialize_database():
    """Initialize the database with required tables if they don't exist"""
    connection = get_connection()
    if not connection:
        logger.error("Failed to initialize database: Could not connect to MySQL")
        return False
    
    cursor = connection.cursor()
    
    try:
        # Create users table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            name VARCHAR(100),
            email VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_admin BOOLEAN DEFAULT FALSE
        )
        """)
        
        # Create scan_history table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            url VARCHAR(2048) NOT NULL,
            domain VARCHAR(255),
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_phishing BOOLEAN DEFAULT FALSE,
            is_suspicious BOOLEAN DEFAULT FALSE,
            risk_score FLOAT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)
        
        # Create scan_features table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_features (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT,
            feature_name VARCHAR(100) NOT NULL,
            feature_value VARCHAR(255),
            risk_level VARCHAR(50),
            FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
        )
        """)
        
        connection.commit()
        logger.info("Database initialized successfully")
        return True
    
    except Error as e:
        logger.error(f"Error initializing database: {e}")
        return False
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_user_by_username(username):
    """Get user data by username"""
    connection = get_connection()
    if not connection:
        return None
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        return user
    
    except Error as e:
        logger.error(f"Error retrieving user: {e}")
        return None
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

_HASH_PREFIXES = ("pbkdf2:", "scrypt:")

def _upgrade_password_hash(user_id, password):
    """Replace a plain-text password with a hash"""
    connection = get_connection()
    if not connection:
        return False
    cursor = connection.cursor()
    try:
        cursor.execute(
            "UPDATE users SET password = %s WHERE id = %s",
            (generate_password_hash(password), user_id)
        )
        connection.commit()
        return True
    except Error as e:
        logger.error(f"Error upgrading password hash: {e}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def verify_user_password(user, password):
    """Check a typed password against the stored value.

    New passwords are stored as hashes. Accounts created before hashing was
    added still hold a plain-text password: it is accepted once and then
    replaced with a hash automatically.
    """
    stored = (user.get("password") or "")
    typed = (password or "")
    if stored.startswith(_HASH_PREFIXES):
        return check_password_hash(stored, typed)
    if hmac.compare_digest(stored.encode("utf-8"), typed.encode("utf-8")):
        _upgrade_password_hash(user["id"], typed)
        return True
    return False

def create_user(username, password, email, is_admin=False):
    """Create a new user"""
    connection = get_connection()
    if not connection:
        logger.error("Failed to create user: Could not connect to database")
        return False
    
    cursor = connection.cursor()
    
    try:
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            logger.warning(f"Username '{username}' already exists")
            return -1  # Return -1 to indicate username already exists
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            logger.warning(f"Email '{email}' already exists")
            return -2  # Return -2 to indicate email already exists
        
        # Insert new user - note we're not setting name field as it's not required
        cursor.execute(
            "INSERT INTO users (username, password, email, is_admin) VALUES (%s, %s, %s, %s)",
            (username, generate_password_hash(password), email, is_admin)
        )
        connection.commit()
        new_user_id = cursor.lastrowid
        logger.info(f"Created new user: {username} (ID: {new_user_id})")
        return new_user_id
    
    except Error as e:
        logger.error(f"Error creating user: {e}")
        print(f"Database error: {e}")  # Print to console for debugging
        return False
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def save_scan(user_id, url, domain, is_phishing, is_suspicious, risk_score, features=None):
    """Save scan results to database"""
    connection = get_connection()
    if not connection:
        return False
    
    cursor = connection.cursor()
    
    try:
        # Insert scan history
        cursor.execute(
            "INSERT INTO scan_history (user_id, url, domain, is_phishing, is_suspicious, risk_score) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, url, domain, is_phishing, is_suspicious, risk_score)
        )
        scan_id = cursor.lastrowid
        
        # Insert features if provided
        if features and scan_id:
            for feature_name, feature_data in features.items():
                if isinstance(feature_data, dict):
                    value = str(feature_data.get('value', ''))
                    risk = feature_data.get('risk', 'low')
                else:
                    value = str(feature_data)
                    risk = 'low'
                
                cursor.execute(
                    "INSERT INTO scan_features (scan_id, feature_name, feature_value, risk_level) VALUES (%s, %s, %s, %s)",
                    (scan_id, feature_name, value, risk)
                )
        
        connection.commit()
        return scan_id
    
    except Error as e:
        logger.error(f"Error saving scan: {e}")
        return False
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_user_scans(user_id, limit=None):
    """Get scan history for a user"""
    connection = get_connection()
    if not connection:
        return []
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        if limit:
            cursor.execute(
                "SELECT * FROM scan_history WHERE user_id = %s ORDER BY scan_date DESC LIMIT %s",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM scan_history WHERE user_id = %s ORDER BY scan_date DESC",
                (user_id,)
            )
        
        scans = cursor.fetchall()
        return scans
    
    except Error as e:
        logger.error(f"Error retrieving user scans: {e}")
        return []
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_scan_details(scan_id):
    """Get detailed information about a scan"""
    connection = get_connection()
    if not connection:
        return None
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Get scan history
        cursor.execute("SELECT * FROM scan_history WHERE id = %s", (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            return None
        
        # Get scan features
        cursor.execute("SELECT * FROM scan_features WHERE scan_id = %s", (scan_id,))
        features = cursor.fetchall()
        
        # Add features to scan data
        scan['features'] = {feature['feature_name']: {
            'value': feature['feature_value'],
            'risk': feature['risk_level']
        } for feature in features}
        
        return scan
    
    except Error as e:
        logger.error(f"Error retrieving scan details: {e}")
        return None
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_stats():
    """Get overall statistics"""
    connection = get_connection()
    if not connection:
        return None
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Get total scans
        cursor.execute("SELECT COUNT(*) as total_scans FROM scan_history")
        total_scans = cursor.fetchone()['total_scans']
        
        # Get safe URLs
        cursor.execute("SELECT COUNT(*) as safe_urls FROM scan_history WHERE is_phishing = FALSE AND is_suspicious = FALSE")
        safe_urls = cursor.fetchone()['safe_urls']
        
        # Get phishing URLs
        cursor.execute("SELECT COUNT(*) as phishing_urls FROM scan_history WHERE is_phishing = TRUE")
        phishing_urls = cursor.fetchone()['phishing_urls']
        
        # Get suspicious URLs
        cursor.execute("SELECT COUNT(*) as suspicious_urls FROM scan_history WHERE is_suspicious = TRUE")
        suspicious_urls = cursor.fetchone()['suspicious_urls']
        
        return {
            'total_scans': total_scans,
            'safe_urls': safe_urls,
            'phishing_urls': phishing_urls,
            'suspicious_urls': suspicious_urls
        }
    
    except Error as e:
        logger.error(f"Error retrieving stats: {e}")
        return None
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Initialize database when module is imported
initialize_database()