from flask import Flask, render_template, request, redirect, url_for, flash, session
import pandas as pd
import pickle
import os
from datetime import datetime
from urllib.parse import urlparse
import random
import logging
from config import SECRET_KEY
import database as db
import enhanced_predictor_fixed as predictor

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', 
                   handlers=[logging.FileHandler('app.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Ensure database is initialized
if not db.initialize_database():
    logger.error("Failed to initialize database. Some features may not work correctly.")

# Load datasets for demo purposes
try:
    phishing_df = pd.read_csv('dataset/phishing.csv')
    legitimate_df = pd.read_csv('dataset/legitimate.csv')
except:
    phishing_df = pd.DataFrame()
    legitimate_df = pd.DataFrame()
    print("Warning: Dataset files not found. Using empty dataframes.")

# Optional: create an admin account on first run.
# Set ADMIN_USERNAME and ADMIN_PASSWORD (and optionally ADMIN_EMAIL and ADMIN_NAME)
# as environment variables before starting the app. No default accounts are created.
_admin_username = os.environ.get("ADMIN_USERNAME")
_admin_password = os.environ.get("ADMIN_PASSWORD")
if _admin_username and _admin_password and not db.get_user_by_username(_admin_username):
    logger.info("Creating admin user from environment settings")
    _admin_id = db.create_user(
        _admin_username,
        _admin_password,
        os.environ.get("ADMIN_EMAIL", f"{_admin_username}@example.com"),
        is_admin=True,
    )
    _admin_name = os.environ.get("ADMIN_NAME")
    if _admin_id and _admin_id > 0 and _admin_name:
        connection = db.get_connection()
        if connection:
            cursor = connection.cursor()
            try:
                cursor.execute("UPDATE users SET name = %s WHERE id = %s", (_admin_name, _admin_id))
                connection.commit()
            except Exception as e:
                logger.error(f"Error updating admin name: {e}")
            finally:
                cursor.close()
                connection.close()

# Get initial stats from database
stats = db.get_stats()

# If database stats are not available, use mock stats
if not stats:
    stats = {
        "total_scans": 0,
        "safe_urls": 0,
        "phishing_urls": 0,
        "suspicious_urls": 0
    }

@app.route('/')
def index():
    # If user is authenticated, redirect to welcome page
    if session.get('authenticated'):
        return redirect(url_for('welcome'))
    # Otherwise, redirect to login page as the default landing page
    return redirect(url_for('login'))

@app.route('/home')
def home():
    # Check if user is authenticated
    if not session.get('authenticated'):
        flash('Please log in to access the home page', 'warning')
        return redirect(url_for('login'))
    
    # Redirect to welcome page as they are the same
    return redirect(url_for('welcome'))

@app.route('/module')
def module():
    # Check if user is authenticated
    if not session.get('authenticated'):
        flash('Please log in to access this page', 'warning')
        return redirect(url_for('login'))
    
    # Redirect to welcome page as the module page doesn't exist separately
    return redirect(url_for('welcome'))

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    # Check if user is authenticated
    if not session.get('authenticated'):
        flash('Please log in to access the URL scanning feature', 'warning')
        return redirect(url_for('login'))
    
    result = None
    is_scanning = False
    recent_scans = []
    
    if request.method == 'POST':
        url = request.form.get('url')
        is_scanning = True
        
        # Extract domain for display
        domain = urlparse(url).netloc
        
        # Use our prediction module to analyze the URL
        logger.info(f"Analyzing URL: {url}")
        prediction_result = predictor.predict_url(url)
        
        # Set is_scanning back to False after the scan is complete
        is_scanning = False
        
        # Extract prediction results
        is_phishing = prediction_result['is_phishing']
        is_suspicious = prediction_result['is_suspicious']
        risk_score = prediction_result['risk_score']
        features = prediction_result['features']
        phishing_indicators = prediction_result.get('phishing_indicators', [])
        
        # Format features for display - simplified for the enhanced predictor
        display_features = features
        
        result = {
            'url': url,
            'domain': domain,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_phishing': is_phishing,
            'is_suspicious': is_suspicious,
            'risk_score': risk_score,
            'features': display_features,
            'phishing_indicators': phishing_indicators,
            'phishing_indicators': phishing_indicators,
        }
        
        # Save scan to database
        user_id = session.get('user_id')
        phishing_indicators = prediction_result.get('phishing_indicators', [])
    
        scan_id = db.save_scan(
            user_id=user_id,
            url=url,
            domain=domain,
            is_phishing=is_phishing,
            is_suspicious=is_suspicious,
            risk_score=risk_score,
            features=display_features
        )
        
        # Update stats
    # Format features for display - simplified for the enhanced predictor
    stats = db.get_stats()
    if not stats:
            stats = {
                "total_scans": 0,
                "safe_urls": 0,
                "phishing_urls": 0,
                "suspicious_urls": 0
            }
    
    # Get recent scans from database
    user_id = session.get('user_id')
    recent_scans = db.get_user_scans(user_id, limit=5)
    
    return render_template('scan_fixed.html', active_page='scan', result=result, is_scanning=is_scanning, recent_scans=recent_scans)

@app.route('/dashboard')
def dashboard():
    try:
        if not session.get('authenticated'):
            flash('Please log in to access the dashboard', 'warning')
            return redirect(url_for('login'))
        
        # Check if this is a new registration (within the current session)
        is_new_user = session.get('is_new_user', False)
        if is_new_user:
            # For new users, redirect to the welcome page
            # We'll keep the flag so the welcome page can show appropriate messages
            return redirect(url_for('welcome'))
        
        # Get recent scans from database
        user_id = session.get('user_id')
        logger.debug(f"Dashboard: Getting scans for user_id: {user_id}")
        recent_scans = db.get_user_scans(user_id, limit=10)
        
        # Get updated stats
        logger.debug("Dashboard: Getting stats")
        current_stats = db.get_stats()
        if current_stats:
            stats.update(current_stats)
        
        logger.debug("Dashboard: Rendering template")
        return render_template('dashboard.html', active_page='dashboard', stats=stats, recent_scans=recent_scans, is_new_user=False)
    except Exception as e:
        logger.error(f"Error in dashboard route: {str(e)}", exc_info=True)
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('welcome'))

@app.route('/education')
def education():
    try:
        # Check if user is authenticated
        if not session.get('authenticated'):
            flash('Please log in to access educational resources', 'warning')
            return redirect(url_for('login'))
        
        logger.debug("Education: Rendering template")
        return render_template('education.html', active_page='education')
    except Exception as e:
        logger.error(f"Error in education route: {str(e)}", exc_info=True)
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('welcome'))

@app.route('/about')
def about():
    # Check if user is authenticated
    if not session.get('authenticated'):
        flash('Please log in to access about page', 'warning')
        return redirect(url_for('login'))
    
    return render_template('about.html', active_page='about')

@app.route('/welcome')
def welcome():
    # If user is not logged in, redirect to login
    if not session.get('authenticated'):
        flash('Please log in to access the welcome page', 'warning')
        return redirect(url_for('login'))
    
    # Get updated stats
    current_stats = db.get_stats()
    if current_stats:
        stats.update(current_stats)
    
    # Check if this is a new registration (within the current session)
    is_new_user = session.get('is_new_user', False)
    if is_new_user:
        # Reset the flag after showing the welcome message
        session['is_new_user'] = False
    
    return render_template('welcome.html', active_page='welcome', stats=stats, is_new_user=is_new_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to welcome page
    if session.get('authenticated'):
        return redirect(url_for('welcome'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.get_user_by_username(username)
        
        if user and db.verify_user_password(user, password):
            session['authenticated'] = True
            session['username'] = username
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            flash('Login successful! Welcome to PhishGuard.', 'success')
            return redirect(url_for('welcome'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', active_page='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # If user is already logged in, redirect to dashboard
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Debug information
        logger.info(f"Registration attempt - Username: {username}, Email: {email}")
        
        # Validate input
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'danger')
            return render_template('register.html', active_page='register')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', active_page='register', 
                                  form_data={'username': username, 'email': email})
        
        # Create new user in database
        # The password is hashed inside db.create_user before it is stored
        try:
            user_id = db.create_user(username, password, email, is_admin=False)
            
            logger.info(f"Registration result - User ID: {user_id}")
            
            if user_id and user_id > 0:  # Successful registration
                # Automatically log in the user after registration
                session['authenticated'] = True
                session['username'] = username
                session['user_id'] = user_id
                session['is_admin'] = False
                session['is_new_user'] = True  # Set flag for new user
                
                flash('Registration successful! Welcome to PhishGuard.', 'success')
                return redirect(url_for('welcome'))
            elif user_id == -1:
                flash('Username already exists. Please choose a different username.', 'danger')
                return render_template('register.html', active_page='register', 
                                      form_data={'email': email})
            elif user_id == -2:
                flash('Email already exists. Please use a different email address.', 'danger')
                return render_template('register.html', active_page='register', 
                                      form_data={'username': username})
            else:
                flash('Registration failed. Please try again later.', 'danger')
                logger.error(f"Registration failed with user_id: {user_id}")
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'danger')
            logger.error(f"Registration exception: {str(e)}")
    
    return render_template('register.html', active_page='register')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))
    
@app.route('/back-to-welcome')
def back_to_welcome():
    """Special route to return to the welcome page"""
    if not session.get('authenticated'):
        flash('Please log in to access the welcome page', 'warning')
        return redirect(url_for('login'))
    
    return redirect(url_for('welcome'))

@app.route('/profile')
def profile():
    if not session.get('authenticated'):
        flash('Please log in to access your profile', 'warning')
        return redirect(url_for('login'))
    
    username = session.get('username')
    user_data = db.get_user_by_username(username)
    
    if not user_data:
        flash('User profile not found', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('profile.html', active_page='profile', user=user_data)

@app.route('/history')
def history():
    if not session.get('authenticated'):
        flash('Please log in to access your scan history', 'warning')
        return redirect(url_for('login'))
    
    # Get all scans for the user from database
    user_id = session.get('user_id')
    scans = db.get_user_scans(user_id)
    
    return render_template('history.html', active_page='history', scans=scans)

@app.route('/scan_details/<int:scan_id>')
def scan_details(scan_id):
    if not session.get('authenticated'):
        flash('Please log in to access scan details', 'warning')
        return redirect(url_for('login'))
    
    # Get scan details from database
    scan = db.get_scan_details(scan_id)
    
    if not scan:
        flash('Scan not found', 'danger')
        return redirect(url_for('history'))
    
    return render_template('scan_details.html', active_page='history', scan=scan)

if __name__ == '__main__':
    app.run(debug=True)