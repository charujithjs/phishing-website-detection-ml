import pandas as pd
import numpy as np
import pickle
import logging
import mysql.connector
from mysql.connector import Error
from config import DB_CONFIG
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
from datetime import datetime
import os

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

def fetch_historical_data():
    """Fetch historical scan data from the database"""
    connection = get_connection()
    if not connection:
        logger.error("Failed to connect to database")
        return pd.DataFrame()
    
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Get all scan history
        cursor.execute("""
            SELECT sh.id, sh.url, sh.domain, sh.is_phishing, sh.is_suspicious, sh.risk_score
            FROM scan_history sh
        """)
        scans = cursor.fetchall()
        
        if not scans:
            logger.warning("No historical scan data found in database")
            return pd.DataFrame()
        
        # Convert to DataFrame
        scans_df = pd.DataFrame(scans)
        
        # For each scan, get its features
        all_scan_data = []
        for scan in scans:
            scan_id = scan['id']
            cursor.execute("""
                SELECT feature_name, feature_value, risk_level
                FROM scan_features
                WHERE scan_id = %s
            """, (scan_id,))
            features = cursor.fetchall()
            
            # Create a dictionary of features for this scan
            feature_dict = {
                'scan_id': scan_id,
                'url': scan['url'],
                'domain': scan['domain'],
                'is_phishing': 1 if scan['is_phishing'] else 0,
                'is_suspicious': 1 if scan['is_suspicious'] else 0,
                'risk_score': scan['risk_score']
            }
            
            # Add features to the dictionary
            for feature in features:
                feature_name = feature['feature_name']
                feature_value = feature['feature_value']
                
                # Try to convert to numeric if possible
                try:
                    if feature_value.lower() == 'true':
                        feature_dict[feature_name] = 1
                    elif feature_value.lower() == 'false':
                        feature_dict[feature_name] = 0
                    else:
                        feature_dict[feature_name] = float(feature_value) if feature_value.replace('.', '', 1).isdigit() else feature_value
                except (ValueError, AttributeError):
                    feature_dict[feature_name] = feature_value
            
            all_scan_data.append(feature_dict)
        
        # Convert to DataFrame
        if all_scan_data:
            return pd.DataFrame(all_scan_data)
        else:
            return pd.DataFrame()
    
    except Error as e:
        logger.error(f"Error fetching historical data: {e}")
        return pd.DataFrame()
    
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def load_dataset_files():
    """Load and combine dataset files"""
    try:
        # Load the main dataset
        urldata_df = pd.read_csv('dataset/urldata.csv')
        logger.info(f"Loaded urldata.csv with {len(urldata_df)} records")
        
        # Try to load additional datasets if available
        additional_dfs = []
        
        try:
            phishing_df = pd.read_csv('dataset/phishing.csv')
            logger.info(f"Loaded phishing.csv with {len(phishing_df)} records")
            additional_dfs.append(phishing_df)
        except Exception as e:
            logger.warning(f"Could not load phishing.csv: {e}")
        
        try:
            legitimate_df = pd.read_csv('dataset/legitimate.csv')
            logger.info(f"Loaded legitimate.csv with {len(legitimate_df)} records")
            additional_dfs.append(legitimate_df)
        except Exception as e:
            logger.warning(f"Could not load legitimate.csv: {e}")
        
        # Combine all datasets
        # Note: This assumes datasets have compatible columns or we handle the differences
        # For now, we'll just return the main dataset
        return urldata_df
    
    except Exception as e:
        logger.error(f"Error loading dataset files: {e}")
        return pd.DataFrame()

def preprocess_data(df):
    """Preprocess the data for training"""
    # Check if DataFrame is empty
    if df.empty:
        logger.error("Empty DataFrame provided for preprocessing")
        return None, None, None, None
    
    # Make a copy to avoid modifying the original
    df_processed = df.copy()
    
    # Handle missing values
    df_processed = df_processed.fillna(0)
    
    # Extract features and target
    X = df_processed.drop(['Label', 'Domain'], axis=1, errors='ignore')
    y = df_processed['Label'] if 'Label' in df_processed.columns else None
    
    if y is None:
        logger.error("Target variable 'Label' not found in the dataset")
        return None, None, None, None
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler

def combine_datasets(file_data, historical_data):
    """Combine file dataset with historical data from database"""
    if historical_data.empty:
        logger.warning("No historical data to combine, using only file data")
        return file_data
    
    if file_data.empty:
        logger.warning("No file data to combine, using only historical data")
        return historical_data
    
    # Map historical data features to match the file data format
    # This is a simplified approach - in a real scenario, you'd need more sophisticated mapping
    
    # Create a new DataFrame for the mapped historical data
    mapped_historical = pd.DataFrame()
    
    # Map 'is_phishing' to 'Label'
    mapped_historical['Label'] = historical_data['is_phishing']
    
    # Map 'domain' to 'Domain'
    mapped_historical['Domain'] = historical_data['domain']
    
    # Map other features based on what's available in historical_data
    feature_mapping = {
        'url_length': 'URL_Length',
        'has_ip': 'Have_IP',
        'has_at': 'Have_At',
        'has_https': 'https_Domain',
        'is_shortened': 'TinyURL',
        'has_prefix_suffix': 'Prefix/Suffix',
        'redirect_count': 'Redirection'
    }
    
    # Initialize all features from file_data with default values
    for col in file_data.columns:
        if col not in ['Label', 'Domain']:
            mapped_historical[col] = 0
    
    # Update with values from historical_data where available
    for hist_col, file_col in feature_mapping.items():
        if hist_col in historical_data.columns and file_col in file_data.columns:
            mapped_historical[file_col] = historical_data[hist_col].astype(int)
    
    # Combine the datasets
    combined_df = pd.concat([file_data, mapped_historical], ignore_index=True)
    
    logger.info(f"Combined dataset has {len(combined_df)} records")
    return combined_df

def train_model(X_train, y_train):
    """Train an XGBoost model"""
    logger.info("Training XGBoost model...")
    
    # Define model parameters
    params = {
        'max_depth': 6,
        'learning_rate': 0.1,
        'n_estimators': 100,
        'objective': 'binary:logistic',
        'booster': 'gbtree',
        'n_jobs': -1,
        'random_state': 42
    }
    
    # Create and train the model
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train)
    
    return model

def evaluate_model(model, X_test, y_test):
    """Evaluate the trained model"""
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    
    # Log results
    logger.info(f"Model Evaluation Results:")
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"F1 Score: {f1:.4f}")
    logger.info(f"Confusion Matrix:\n{conf_matrix}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': conf_matrix
    }

def save_model(model, scaler, metrics):
    """Save the trained model and evaluation metrics"""
    # Create a timestamp for versioning
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save the model
    model_filename = f"XGBoostClassifier.pickle.dat"
    with open(model_filename, 'wb') as f:
        pickle.dump(model, f)
    
    # Save the scaler
    scaler_filename = f"StandardScaler.pickle.dat"
    with open(scaler_filename, 'wb') as f:
        pickle.dump(scaler, f)
    
    # Save metrics to a text file
    metrics_filename = f"model_metrics_{timestamp}.txt"
    with open(metrics_filename, 'w') as f:
        f.write(f"Model Training Metrics - {timestamp}\n")
        f.write(f"Accuracy: {metrics['accuracy']:.4f}\n")
        f.write(f"Precision: {metrics['precision']:.4f}\n")
        f.write(f"Recall: {metrics['recall']:.4f}\n")
        f.write(f"F1 Score: {metrics['f1']:.4f}\n")
        f.write(f"Confusion Matrix:\n{metrics['confusion_matrix']}\n")
    
    logger.info(f"Model saved as {model_filename}")
    logger.info(f"Scaler saved as {scaler_filename}")
    logger.info(f"Metrics saved as {metrics_filename}")
    
    return model_filename, scaler_filename, metrics_filename

def main():
    """Main function to train the model"""
    logger.info("Starting URL phishing detection model training")
    
    # Step 1: Load dataset files
    logger.info("Loading dataset files...")
    file_data = load_dataset_files()
    
    if file_data.empty:
        logger.error("Failed to load dataset files. Aborting training.")
        return
    
    # Step 2: Fetch historical data from database
    logger.info("Fetching historical data from database...")
    historical_data = fetch_historical_data()
    
    # Step 3: Combine datasets
    logger.info("Combining datasets...")
    combined_data = combine_datasets(file_data, historical_data)
    
    # Step 4: Preprocess the data
    logger.info("Preprocessing data...")
    X_train, X_test, y_train, y_test, scaler = preprocess_data(combined_data)
    
    if X_train is None:
        logger.error("Data preprocessing failed. Aborting training.")
        return
    
    # Step 5: Train the model
    logger.info("Training model...")
    model = train_model(X_train, y_train)
    
    # Step 6: Evaluate the model
    logger.info("Evaluating model...")
    metrics = evaluate_model(model, X_test, y_test)
    
    # Step 7: Save the model
    logger.info("Saving model...")
    model_file, scaler_file, metrics_file = save_model(model, scaler, metrics)
    
    logger.info("Model training completed successfully!")
    logger.info(f"Model saved to {model_file}")
    logger.info(f"Scaler saved to {scaler_file}")
    logger.info(f"Metrics saved to {metrics_file}")

if __name__ == "__main__":
    main()