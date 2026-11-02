import pandas as pd
import numpy as np
import pickle
import logging
from urllib.parse import urlparse
import re
import os
import tldextract
from datetime import datetime
import whois
import requests
from bs4 import BeautifulSoup
import socket
import ssl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_model()
    
    def load_model(self):
        """Load the trained model and scaler"""
        try:
            model_path = "XGBoostClassifier.pickle.dat"
            scaler_path = "StandardScaler.pickle.dat"
            
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info(f"Model loaded from {model_path}")
            else:
                logger.error(f"Model file not found at {model_path}")
            
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info(f"Scaler loaded from {scaler_path}")
            else:
                logger.warning(f"Scaler file not found at {scaler_path}")
        
        except Exception as e:
            logger.error(f"Error loading model: {e}")
    
    def extract_features(self, url):
        """Extract features from a URL for prediction"""
        features = {}
        
        try:
            # Basic URL parsing
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Extract domain information
            ext = tldextract.extract(url)
            domain_name = ext.domain + '.' + ext.suffix if ext.suffix else ext.domain
            
            # Feature: URL Length
            features['URL_Length'] = len(url)
            
            # Feature: URL Depth
            path_parts = parsed_url.path.split('/')
            features['URL_Depth'] = len([p for p in path_parts if p])
            
            # Feature: Has IP Address
            has_ip = self._has_ip_address(domain)
            features['Have_IP'] = 1 if has_ip else 0
            
            # Feature: Has @ Symbol
            features['Have_At'] = 1 if '@' in url else 0
            
            # Feature: Has HTTPS
            features['https_Domain'] = 1 if parsed_url.scheme == 'https' else 0
            
            # Feature: Is Shortened URL
            shortened_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly', 'rebrand.ly']
            features['TinyURL'] = 1 if any(sd in domain for sd in shortened_domains) else 0
            
            # Feature: Has Prefix/Suffix
            features['Prefix/Suffix'] = 1 if '-' in domain_name else 0
            
            # Feature: Redirection
            features['Redirection'] = self._count_redirects(url)
            
            # Feature: DNS Record (try to check if domain exists)
            try:
                socket.gethostbyname(domain)
                features['DNS_Record'] = 1
            except:
                features['DNS_Record'] = 0
            
            # Feature: Domain Age (simplified)
            features['Domain_Age'] = self._get_domain_age(domain_name)
            
            # Feature: Domain End (time until expiration - simplified)
            features['Domain_End'] = 1  # Default to 1 (not expiring soon)
            
            # Feature: iFrame
            features['iFrame'] = 0  # Default to 0, would require page content analysis
            
            # Feature: Mouse Over
            features['Mouse_Over'] = 0  # Default to 0, would require page content analysis
            
            # Feature: Right Click
            features['Right_Click'] = 1  # Default to 1, would require page content analysis
            
            # Feature: Web Forwards
            features['Web_Forwards'] = 0  # Default to 0, would require deeper analysis
            
            # Feature: Web Traffic (simplified)
            features['Web_Traffic'] = self._check_web_traffic(domain_name)
            
            # Return features as a DataFrame
            return pd.DataFrame([features])
        
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {e}")
            # Return default features
            default_features = {
                'Have_IP': 0, 'Have_At': 0, 'URL_Length': 1, 'URL_Depth': 1,
                'Redirection': 0, 'https_Domain': 0, 'TinyURL': 0, 'Prefix/Suffix': 0,
                'DNS_Record': 0, 'Web_Traffic': 0, 'Domain_Age': 0, 'Domain_End': 0,
                'iFrame': 0, 'Mouse_Over': 0, 'Right_Click': 0, 'Web_Forwards': 0
            }
            return pd.DataFrame([default_features])
    
    def _has_ip_address(self, domain):
        """Check if domain contains an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, domain))
    
    def _count_redirects(self, url, max_redirects=10):
        """Count the number of redirects for a URL"""
        try:
            response = requests.get(url, allow_redirects=True, timeout=5)
            return len(response.history) if response.history else 0
        except:
            return 0
    
    def _get_domain_age(self, domain):
        """Get domain age (simplified)"""
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.now() - creation_date).days
                return 1 if age_days > 180 else 0  # Consider domains older than 6 months as established
            return 0
        except:
            return 0
    
    def _check_web_traffic(self, domain):
        """Check web traffic (simplified)"""
        try:
            # This is a simplified approach - in a real scenario, you'd use a service like Alexa or SimilarWeb
            response = requests.get(f"https://{domain}", timeout=5)
            return 1 if response.status_code == 200 else 0
        except:
            return 0
    
    def predict(self, url):
        """Predict if a URL is phishing or legitimate"""
        if not self.model:
            logger.error("Model not loaded. Cannot make prediction.")
            return {
                'is_phishing': False,
                'is_suspicious': True,
                'risk_score': 5.0,
                'features': {}
            }
        
        try:
            # Extract features
            features_df = self.extract_features(url)
            
            # Store original features for return
            original_features = features_df.iloc[0].to_dict()
            
            # Scale features if scaler is available
            if self.scaler:
                features_scaled = self.scaler.transform(features_df)
            else:
                features_scaled = features_df.values
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            
            # Get probability scores if available
            try:
                proba = self.model.predict_proba(features_scaled)[0]
                risk_score = proba[1] * 10  # Scale to 0-10
            except:
                risk_score = 5.0 if prediction else 1.0
            
            # Determine if suspicious (medium risk)
            is_suspicious = False
            if not prediction and risk_score > 3.0:
                is_suspicious = True
            
            # Create feature risk assessments
            feature_risks = {}
            for feature, value in original_features.items():
                if feature in ['Have_IP', 'Have_At', 'TinyURL', 'Prefix/Suffix']:
                    risk = 'high' if value == 1 else 'low'
                elif feature == 'https_Domain':
                    risk = 'low' if value == 1 else 'medium'
                elif feature == 'URL_Length':
                    risk = 'high' if value > 75 else 'medium' if value > 50 else 'low'
                elif feature == 'URL_Depth':
                    risk = 'medium' if value > 4 else 'low'
                elif feature == 'Redirection':
                    risk = 'high' if value > 3 else 'medium' if value > 1 else 'low'
                else:
                    risk = 'low'
                
                feature_risks[feature] = {
                    'value': value,
                    'risk': risk
                }
            
            return {
                'is_phishing': bool(prediction),
                'is_suspicious': is_suspicious,
                'risk_score': round(float(risk_score), 1),
                'features': feature_risks
            }
        
        except Exception as e:
            logger.error(f"Error making prediction for URL {url}: {e}")
            return {
                'is_phishing': False,
                'is_suspicious': True,
                'risk_score': 5.0,
                'features': {}
            }

# Singleton instance
predictor = PhishingPredictor()

def predict_url(url):
    """Function to predict if a URL is phishing or legitimate"""
    return predictor.predict(url)