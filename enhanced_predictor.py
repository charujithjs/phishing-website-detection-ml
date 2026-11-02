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
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedPhishingPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_importance = {}
        self.phishing_patterns = {}
        self.load_or_train_model()
    
    def load_or_train_model(self):
        """Load the trained model or train a new one from the dataset"""
        model_path = "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_model.pkl"
        scaler_path = "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_scaler.pkl"
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded existing enhanced model and scaler")
                self._load_phishing_patterns()
                return
            except Exception as e:
                logger.error(f"Error loading model: {e}")
        
        # If model doesn't exist or couldn't be loaded, train a new one
        logger.info("Training new enhanced model from dataset")
        self._train_model_from_dataset()
    
    def _train_model_from_dataset(self):
        """Train a new model from the phishing dataset"""
        try:
            # Load the dataset
            dataset_path = "c:/Users/charu/OneDrive/Desktop/project/dataset/dataset_phishing.csv"
            df = pd.read_csv(dataset_path)
            
            logger.info(f"Loaded dataset with {len(df)} records")
            
            # Select relevant features for our model
            # We'll use a subset of features that don't require the actual URL
            features = [
                'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 
                'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
                'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
                'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
                'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 
                'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
                'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 
                'nb_subdomains', 'prefix_suffix', 'random_domain', 
                'shortening_service', 'path_extension', 'nb_redirection',
                'nb_external_redirection', 'length_words_raw', 'char_repeat',
                'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
                'longest_words_raw', 'longest_word_host', 'longest_word_path',
                'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints',
                'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
                'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
                'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
                'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
                'ratio_intErrors', 'ratio_extErrors', 'login_form',
                'external_favicon', 'links_in_tags', 'submit_email',
                'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
                'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
                'empty_title', 'domain_in_title', 'domain_with_copyright',
                'whois_registered_domain', 'domain_registration_length',
                'domain_age', 'web_traffic', 'dns_record', 'google_index',
                'page_rank'
            ]
            
            # Prepare X (features) and y (target)
            X = df[features]
            y = df['status'].apply(lambda x: 1 if x == 'phishing' else 0)
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale the features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            
            # Train a Random Forest model
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate the model
            X_test_scaled = self.scaler.transform(X_test)
            accuracy = self.model.score(X_test_scaled, y_test)
            logger.info(f"Model trained with accuracy: {accuracy:.4f}")
            
            # Save feature importance
            self.feature_importance = dict(zip(features, self.model.feature_importances_))
            
            # Extract phishing patterns
            self._extract_phishing_patterns(df, features)
            
            # Save the model and scaler
            joblib.dump(self.model, "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_model.pkl")
            joblib.dump(self.scaler, "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_scaler.pkl")
            
            # Save phishing patterns
            with open("c:/Users/charu/OneDrive/Desktop/project/models/phishing_patterns.pkl", 'wb') as f:
                pickle.dump(self.phishing_patterns, f)
                
            logger.info("Model, scaler, and phishing patterns saved successfully")
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            # Fallback to a simple model if training fails
            self.model = RandomForestClassifier(n_estimators=10)
            self.scaler = StandardScaler()
    
    def _extract_phishing_patterns(self, df, features):
        """Extract patterns that are common in phishing URLs"""
        phishing_df = df[df['status'] == 'phishing']
        legitimate_df = df[df['status'] == 'legitimate']
        
        patterns = {}
        
        # For each feature, calculate the mean and std for phishing and legitimate URLs
        for feature in features:
            phish_mean = phishing_df[feature].mean()
            phish_std = phishing_df[feature].std()
            legit_mean = legitimate_df[feature].mean()
            legit_std = legitimate_df[feature].std()
            
            # Calculate the difference between phishing and legitimate
            diff = abs(phish_mean - legit_mean)
            
            # If the difference is significant, add it to patterns
            if diff > 0.5 * (phish_std + legit_std) / 2:
                patterns[feature] = {
                    'phish_mean': phish_mean,
                    'phish_std': phish_std,
                    'legit_mean': legit_mean,
                    'legit_std': legit_std,
                    'importance': self.feature_importance.get(feature, 0)
                }
        
        # Sort patterns by importance
        self.phishing_patterns = {k: v for k, v in sorted(
            patterns.items(), 
            key=lambda item: item[1]['importance'], 
            reverse=True
        )}
        
        logger.info(f"Extracted {len(self.phishing_patterns)} significant phishing patterns")
    
    def _load_phishing_patterns(self):
        """Load phishing patterns from file"""
        try:
            patterns_path = "c:/Users/charu/OneDrive/Desktop/project/models/phishing_patterns.pkl"
            if os.path.exists(patterns_path):
                with open(patterns_path, 'rb') as f:
                    self.phishing_patterns = pickle.load(f)
                logger.info(f"Loaded {len(self.phishing_patterns)} phishing patterns")
            else:
                logger.warning("Phishing patterns file not found")
        except Exception as e:
            logger.error(f"Error loading phishing patterns: {e}")
    
    def extract_features_from_url(self, url):
        """Extract features from a URL for prediction"""
        features = {}
        
        try:
            # Basic URL parsing
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Extract domain information
            ext = tldextract.extract(url)
            domain_name = ext.domain + '.' + ext.suffix if ext.suffix else ext.domain
            
            # Feature: length_url
            features['length_url'] = len(url)
            
            # Feature: length_hostname
            features['length_hostname'] = len(domain)
            
            # Feature: ip
            features['ip'] = 1 if self._has_ip_address(domain) else 0
            
            # Feature: nb_dots
            features['nb_dots'] = url.count('.')
            
            # Feature: nb_hyphens
            features['nb_hyphens'] = url.count('-')
            
            # Feature: nb_at
            features['nb_at'] = url.count('@')
            
            # Feature: nb_qm
            features['nb_qm'] = url.count('?')
            
            # Feature: nb_and
            features['nb_and'] = url.count('&')
            
            # Feature: nb_or
            features['nb_or'] = url.count('|')
            
            # Feature: nb_eq
            features['nb_eq'] = url.count('=')
            
            # Feature: nb_underscore
            features['nb_underscore'] = url.count('_')
            
            # Feature: nb_tilde
            features['nb_tilde'] = url.count('~')
            
            # Feature: nb_percent
            features['nb_percent'] = url.count('%')
            
            # Feature: nb_slash
            features['nb_slash'] = url.count('/')
            
            # Feature: nb_star
            features['nb_star'] = url.count('*')
            
            # Feature: nb_colon
            features['nb_colon'] = url.count(':')
            
            # Feature: nb_comma
            features['nb_comma'] = url.count(',')
            
            # Feature: nb_semicolumn
            features['nb_semicolumn'] = url.count(';')
            
            # Feature: nb_dollar
            features['nb_dollar'] = url.count('$')
            
            # Feature: nb_space
            features['nb_space'] = url.count(' ')
            
            # Feature: nb_www
            features['nb_www'] = 1 if 'www' in domain.lower() else 0
            
            # Feature: nb_com
            features['nb_com'] = 1 if '.com' in url.lower() else 0
            
            # Feature: nb_dslash
            features['nb_dslash'] = url.count('//')
            
            # Feature: http_in_path
            features['http_in_path'] = 1 if 'http' in path.lower() else 0
            
            # Feature: https_token
            features['https_token'] = 1 if parsed_url.scheme == 'https' else 0
            
            # Feature: ratio_digits_url
            digits_count = sum(c.isdigit() for c in url)
            features['ratio_digits_url'] = digits_count / len(url) if len(url) > 0 else 0
            
            # Feature: ratio_digits_host
            host_digits_count = sum(c.isdigit() for c in domain)
            features['ratio_digits_host'] = host_digits_count / len(domain) if len(domain) > 0 else 0
            
            # Feature: punycode
            features['punycode'] = 1 if 'xn--' in domain.lower() else 0
            
            # Feature: port
            features['port'] = 1 if ':' in domain else 0
            
            # Feature: tld_in_path
            tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int']
            features['tld_in_path'] = 1 if any(tld in path.lower() for tld in tlds) else 0
            
            # Feature: tld_in_subdomain
            features['tld_in_subdomain'] = 1 if any(tld in ext.subdomain.lower() for tld in tlds) else 0
            
            # Feature: abnormal_subdomain
            features['abnormal_subdomain'] = 1 if len(ext.subdomain) > 20 else 0
            
            # Feature: nb_subdomains
            features['nb_subdomains'] = domain.count('.') + 1
            
            # Feature: prefix_suffix
            features['prefix_suffix'] = 1 if '-' in domain_name else 0
            
            # Feature: random_domain
            # This is a complex feature, we'll simplify
            features['random_domain'] = 0
            
            # Feature: shortening_service
            shortening_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'ow.ly', 'rebrand.ly']
            features['shortening_service'] = 1 if any(service in domain.lower() for service in shortening_services) else 0
            
            # Feature: path_extension
            common_extensions = ['.html', '.php', '.asp', '.aspx', '.jsp', '.js', '.css']
            features['path_extension'] = 1 if any(ext in path.lower() for ext in common_extensions) else 0
            
            # Feature: nb_redirection
            features['nb_redirection'] = self._count_redirects(url)
            
            # Feature: nb_external_redirection
            # This requires content analysis, we'll set a default
            features['nb_external_redirection'] = 0
            
            # Feature: length_words_raw
            words = re.findall(r'\w+', url)
            features['length_words_raw'] = len(words)
            
            # Feature: char_repeat
            features['char_repeat'] = self._count_repeated_chars(url)
            
            # Feature: shortest_words_raw
            features['shortest_words_raw'] = min([len(word) for word in words]) if words else 0
            
            # Feature: shortest_word_host
            host_words = re.findall(r'\w+', domain)
            features['shortest_word_host'] = min([len(word) for word in host_words]) if host_words else 0
            
            # Feature: shortest_word_path
            path_words = re.findall(r'\w+', path)
            features['shortest_word_path'] = min([len(word) for word in path_words]) if path_words else 0
            
            # Feature: longest_words_raw
            features['longest_words_raw'] = max([len(word) for word in words]) if words else 0
            
            # Feature: longest_word_host
            features['longest_word_host'] = max([len(word) for word in host_words]) if host_words else 0
            
            # Feature: longest_word_path
            features['longest_word_path'] = max([len(word) for word in path_words]) if path_words else 0
            
            # Feature: avg_words_raw
            features['avg_words_raw'] = sum([len(word) for word in words]) / len(words) if words else 0
            
            # Feature: avg_word_host
            features['avg_word_host'] = sum([len(word) for word in host_words]) / len(host_words) if host_words else 0
            
            # Feature: avg_word_path
            features['avg_word_path'] = sum([len(word) for word in path_words]) / len(path_words) if path_words else 0
            
            # The remaining features require content analysis or external services
            # We'll set default values for them
            default_features = {
                'phish_hints': 0,
                'domain_in_brand': 0,
                'brand_in_subdomain': 0,
                'brand_in_path': 0,
                'suspecious_tld': 0,
                'statistical_report': 0,
                'nb_hyperlinks': 0,
                'ratio_intHyperlinks': 0,
                'ratio_extHyperlinks': 0,
                'ratio_nullHyperlinks': 0,
                'nb_extCSS': 0,
                'ratio_intRedirection': 0,
                'ratio_extRedirection': 0,
                'ratio_intErrors': 0,
                'ratio_extErrors': 0,
                'login_form': 0,
                'external_favicon': 0,
                'links_in_tags': 0,
                'submit_email': 0,
                'ratio_intMedia': 0,
                'ratio_extMedia': 0,
                'sfh': 0,
                'iframe': 0,
                'popup_window': 0,
                'safe_anchor': 0,
                'onmouseover': 0,
                'right_clic': 0,
                'empty_title': 0,
                'domain_in_title': 0,
                'domain_with_copyright': 0,
                'whois_registered_domain': 0,
                'domain_registration_length': 0,
                'domain_age': 0,
                'web_traffic': 0,
                'dns_record': 0,
                'google_index': 0,
                'page_rank': 0
            }
            
            # Update features with default values
            features.update(default_features)
            
            # Try to get some content-based features if possible
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Feature: nb_hyperlinks
                    links = soup.find_all('a')
                    features['nb_hyperlinks'] = len(links)
                    
                    # Feature: login_form
                    forms = soup.find_all('form')
                    password_inputs = soup.find_all('input', {'type': 'password'})
                    features['login_form'] = 1 if forms and password_inputs else 0
                    
                    # Feature: iframe
                    iframes = soup.find_all('iframe')
                    features['iframe'] = 1 if iframes else 0
                    
                    # Feature: popup_window
                    popup_js = ['window.open', 'popup', 'alert(']
                    scripts = soup.find_all('script')
                    script_text = ' '.join([script.text for script in scripts])
                    features['popup_window'] = 1 if any(js in script_text for js in popup_js) else 0
                    
                    # Feature: onmouseover
                    onmouseover_elements = soup.find_all(attrs={"onmouseover": True})
                    features['onmouseover'] = 1 if onmouseover_elements else 0
                    
                    # Feature: right_clic
                    right_click_disabled = 'oncontextmenu="return false"' in response.text
                    features['right_clic'] = 0 if right_click_disabled else 1
                    
                    # Feature: empty_title
                    title = soup.find('title')
                    features['empty_title'] = 0 if title and title.text.strip() else 1
                    
                    # Feature: domain_in_title
                    features['domain_in_title'] = 1 if title and domain_name.lower() in title.text.lower() else 0
            except:
                pass
            
            # Try to get DNS record
            try:
                socket.gethostbyname(domain)
                features['dns_record'] = 1
            except:
                features['dns_record'] = 0
            
            # Try to get domain age
            try:
                domain_info = whois.whois(domain_name)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    age_days = (datetime.now() - creation_date).days
                    features['domain_age'] = age_days
                    features['whois_registered_domain'] = 1
                else:
                    features['domain_age'] = -1
                    features['whois_registered_domain'] = 0
            except:
                features['domain_age'] = -1
                features['whois_registered_domain'] = 0
            
            return pd.DataFrame([features])
        
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {e}")
            # Return default features
            default_features = {
                'length_url': 0, 'length_hostname': 0, 'ip': 0, 'nb_dots': 0,
                'nb_hyphens': 0, 'nb_at': 0, 'nb_qm': 0, 'nb_and': 0,
                'nb_or': 0, 'nb_eq': 0, 'nb_underscore': 0, 'nb_tilde': 0,
                'nb_percent': 0, 'nb_slash': 0, 'nb_star': 0, 'nb_colon': 0,
                'nb_comma': 0, 'nb_semicolumn': 0, 'nb_dollar': 0, 'nb_space': 0,
                'nb_www': 0, 'nb_com': 0, 'nb_dslash': 0, 'http_in_path': 0,
                'https_token': 0, 'ratio_digits_url': 0, 'ratio_digits_host': 0,
                'punycode': 0, 'port': 0, 'tld_in_path': 0, 'tld_in_subdomain': 0,
                'abnormal_subdomain': 0, 'nb_subdomains': 0, 'prefix_suffix': 0,
                'random_domain': 0, 'shortening_service': 0, 'path_extension': 0,
                'nb_redirection': 0, 'nb_external_redirection': 0, 'length_words_raw': 0,
                'char_repeat': 0, 'shortest_words_raw': 0, 'shortest_word_host': 0,
                'shortest_word_path': 0, 'longest_words_raw': 0, 'longest_word_host': 0,
                'longest_word_path': 0, 'avg_words_raw': 0, 'avg_word_host': 0,
                'avg_word_path': 0, 'phish_hints': 0, 'domain_in_brand': 0,
                'brand_in_subdomain': 0, 'brand_in_path': 0, 'suspecious_tld': 0,
                'statistical_report': 0, 'nb_hyperlinks': 0, 'ratio_intHyperlinks': 0,
                'ratio_extHyperlinks': 0, 'ratio_nullHyperlinks': 0, 'nb_extCSS': 0,
                'ratio_intRedirection': 0, 'ratio_extRedirection': 0, 'ratio_intErrors': 0,
                'ratio_extErrors': 0, 'login_form': 0, 'external_favicon': 0,
                'links_in_tags': 0, 'submit_email': 0, 'ratio_intMedia': 0,
                'ratio_extMedia': 0, 'sfh': 0, 'iframe': 0, 'popup_window': 0,
                'safe_anchor': 0, 'onmouseover': 0, 'right_clic': 0, 'empty_title': 0,
                'domain_in_title': 0, 'domain_with_copyright': 0, 'whois_registered_domain': 0,
                'domain_registration_length': 0, 'domain_age': 0, 'web_traffic': 0,
                'dns_record': 0, 'google_index': 0, 'page_rank': 0
            }
            return pd.DataFrame([default_features])
    
    def _has_ip_address(self, domain):
        """Check if domain contains an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, domain))
    
    def _count_redirects(self, url, max_redirects=5):
        """Count the number of redirects for a URL"""
        try:
            response = requests.get(url, allow_redirects=True, timeout=3)
            return len(response.history) if response.history else 0
        except:
            return 0
    
    def _count_repeated_chars(self, text):
        """Count the number of repeated characters in a string"""
        if not text:
            return 0
        
        count = 0
        for i in range(len(text) - 1):
            if text[i] == text[i+1]:
                count += 1
        return count
    
    def predict(self, url):
        """Predict if a URL is phishing or legitimate"""
        if not self.model:
            logger.error("Model not loaded. Cannot make prediction.")
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'features': {},
                'phishing_indicators': []
            }
        
        try:
            # Extract features
            features_df = self.extract_features_from_url(url)
            
            # Store original features for return
            original_features = features_df.iloc[0].to_dict()
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            
            # Get probability scores
            proba = self.model.predict_proba(features_scaled)[0]
            confidence = proba[1] if prediction else 1 - proba[1]
            
            # Identify phishing indicators
            phishing_indicators = self._get_phishing_indicators(original_features)
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(confidence),
                'features': original_features,
                'phishing_indicators': phishing_indicators
            }
        
        except Exception as e:
            logger.error(f"Error making prediction for URL {url}: {e}")
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'features': {},
                'phishing_indicators': []
            }
    
    def _get_phishing_indicators(self, features):
        """Identify features that indicate phishing based on patterns"""
        indicators = []
        
        for feature, pattern in self.phishing_patterns.items():
            if feature not in features:
                continue
                
            value = features[feature]
            phish_mean = pattern['phish_mean']
            phish_std = pattern['phish_std']
            legit_mean = pattern['legit_mean']
            legit_std = pattern['legit_std']
            importance = pattern['importance']
            
            # Check if the feature value is closer to phishing mean than legitimate mean
            phish_distance = abs(value - phish_mean)
            legit_distance = abs(value - legit_mean)
            
            if phish_distance < legit_distance:
                # Calculate a score based on how close it is to phishing mean
                score = 1 - (phish_distance / (phish_std * 3 if phish_std > 0 else 1))
                score = max(0, min(1, score))  # Clamp between 0 and 1
                
                # Only include significant indicators
                if score > 0.6 and importance > 0.01:
                    indicators.append({
                        'feature': feature,
                        'value': value,
                        'score': score,
                        'importance': importance
                    })
        
        # Sort by importance * score
        indicators.sort(key=lambda x: x['importance'] * x['score'], reverse=True)
        
        # Return top 10 indicators
        return indicators[:10]

# Create an instance of the enhanced predictor
enhanced_predictor = EnhancedPhishingPredictor()

def predict_url(url):
    """Function to predict if a URL is phishing or legitimate"""
    result = enhanced_predictor.predict(url)
    
    # Format the result to match the expected output format
    phishing_indicators = result['phishing_indicators']
    
    # Create feature risks based on indicators
    feature_risks = {}
    for feature, value in result['features'].items():
        # Check if this feature is in the indicators
        indicator = next((i for i in phishing_indicators if i['feature'] == feature), None)
        
        if indicator:
            risk_score = indicator['score']
            if risk_score > 0.8:
                risk = 'high'
            elif risk_score > 0.6:
                risk = 'medium'
            else:
                risk = 'low'
        else:
            risk = 'low'
        
        feature_risks[feature] = {
            'value': value,
            'risk': risk
        }
    
    # Calculate overall risk score (0-10)
    risk_score = result['confidence'] * 10
    
    # Determine if suspicious (medium risk)
    is_suspicious = False
    if not result['is_phishing'] and risk_score > 3.0:
        is_suspicious = True
    
    return {
        'is_phishing': result['is_phishing'],
        'is_suspicious': is_suspicious,
        'risk_score': round(float(risk_score), 1),
        'features': feature_risks,
        'phishing_indicators': [
            {
                'feature': i['feature'],
                'value': i['value'],
                'importance': round(i['importance'] * 100, 2)
            } for i in phishing_indicators
        ]
    }import pandas as pd
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedPhishingPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_importance = {}
        self.phishing_patterns = {}
        self.load_or_train_model()
    
    def load_or_train_model(self):
        """Load the trained model or train a new one from the dataset"""
        model_path = "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_model.pkl"
        scaler_path = "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_scaler.pkl"
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded existing enhanced model and scaler")
                self._load_phishing_patterns()
                return
            except Exception as e:
                logger.error(f"Error loading model: {e}")
        
        # If model doesn't exist or couldn't be loaded, train a new one
        logger.info("Training new enhanced model from dataset")
        self._train_model_from_dataset()
    
    def _train_model_from_dataset(self):
        """Train a new model from the phishing dataset"""
        try:
            # Load the dataset
            dataset_path = "c:/Users/charu/OneDrive/Desktop/project/dataset/dataset_phishing.csv"
            df = pd.read_csv(dataset_path)
            
            logger.info(f"Loaded dataset with {len(df)} records")
            
            # Select relevant features for our model
            # We'll use a subset of features that don't require the actual URL
            features = [
                'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 
                'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
                'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
                'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
                'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 
                'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
                'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 
                'nb_subdomains', 'prefix_suffix', 'random_domain', 
                'shortening_service', 'path_extension', 'nb_redirection',
                'nb_external_redirection', 'length_words_raw', 'char_repeat',
                'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
                'longest_words_raw', 'longest_word_host', 'longest_word_path',
                'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints',
                'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
                'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
                'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
                'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
                'ratio_intErrors', 'ratio_extErrors', 'login_form',
                'external_favicon', 'links_in_tags', 'submit_email',
                'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
                'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
                'empty_title', 'domain_in_title', 'domain_with_copyright',
                'whois_registered_domain', 'domain_registration_length',
                'domain_age', 'web_traffic', 'dns_record', 'google_index',
                'page_rank'
            ]
            
            # Prepare X (features) and y (target)
            X = df[features]
            y = df['status'].apply(lambda x: 1 if x == 'phishing' else 0)
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale the features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            
            # Train a Random Forest model
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate the model
            X_test_scaled = self.scaler.transform(X_test)
            accuracy = self.model.score(X_test_scaled, y_test)
            logger.info(f"Model trained with accuracy: {accuracy:.4f}")
            
            # Save feature importance
            self.feature_importance = dict(zip(features, self.model.feature_importances_))
            
            # Extract phishing patterns
            self._extract_phishing_patterns(df, features)
            
            # Save the model and scaler
            joblib.dump(self.model, "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_model.pkl")
            joblib.dump(self.scaler, "c:/Users/charu/OneDrive/Desktop/project/models/enhanced_scaler.pkl")
            
            # Save phishing patterns
            with open("c:/Users/charu/OneDrive/Desktop/project/models/phishing_patterns.pkl", 'wb') as f:
                pickle.dump(self.phishing_patterns, f)
                
            logger.info("Model, scaler, and phishing patterns saved successfully")
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            # Fallback to a simple model if training fails
            self.model = RandomForestClassifier(n_estimators=10)
            self.scaler = StandardScaler()
    
    def _extract_phishing_patterns(self, df, features):
        """Extract patterns that are common in phishing URLs"""
        phishing_df = df[df['status'] == 'phishing']
        legitimate_df = df[df['status'] == 'legitimate']
        
        patterns = {}
        
        # For each feature, calculate the mean and std for phishing and legitimate URLs
        for feature in features:
            phish_mean = phishing_df[feature].mean()
            phish_std = phishing_df[feature].std()
            legit_mean = legitimate_df[feature].mean()
            legit_std = legitimate_df[feature].std()
            
            # Calculate the difference between phishing and legitimate
            diff = abs(phish_mean - legit_mean)
            
            # If the difference is significant, add it to patterns
            if diff > 0.5 * (phish_std + legit_std) / 2:
                patterns[feature] = {
                    'phish_mean': phish_mean,
                    'phish_std': phish_std,
                    'legit_mean': legit_mean,
                    'legit_std': legit_std,
                    'importance': self.feature_importance.get(feature, 0)
                }
        
        # Sort patterns by importance
        self.phishing_patterns = {k: v for k, v in sorted(
            patterns.items(), 
            key=lambda item: item[1]['importance'], 
            reverse=True
        )}
        
        logger.info(f"Extracted {len(self.phishing_patterns)} significant phishing patterns")
    
    def _load_phishing_patterns(self):
        """Load phishing patterns from file"""
        try:
            patterns_path = "c:/Users/charu/OneDrive/Desktop/project/models/phishing_patterns.pkl"
            if os.path.exists(patterns_path):
                with open(patterns_path, 'rb') as f:
                    self.phishing_patterns = pickle.load(f)
                logger.info(f"Loaded {len(self.phishing_patterns)} phishing patterns")
            else:
                logger.warning("Phishing patterns file not found")
        except Exception as e:
            logger.error(f"Error loading phishing patterns: {e}")
    
    def extract_features_from_url(self, url):
        """Extract features from a URL for prediction"""
        features = {}
        
        try:
            # Basic URL parsing
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Extract domain information
            ext = tldextract.extract(url)
            domain_name = ext.domain + '.' + ext.suffix if ext.suffix else ext.domain
            
            # Feature: length_url
            features['length_url'] = len(url)
            
            # Feature: length_hostname
            features['length_hostname'] = len(domain)
            
            # Feature: ip
            features['ip'] = 1 if self._has_ip_address(domain) else 0
            
            # Feature: nb_dots
            features['nb_dots'] = url.count('.')
            
            # Feature: nb_hyphens
            features['nb_hyphens'] = url.count('-')
            
            # Feature: nb_at
            features['nb_at'] = url.count('@')
            
            # Feature: nb_qm
            features['nb_qm'] = url.count('?')
            
            # Feature: nb_and
            features['nb_and'] = url.count('&')
            
            # Feature: nb_or
            features['nb_or'] = url.count('|')
            
            # Feature: nb_eq
            features['nb_eq'] = url.count('=')
            
            # Feature: nb_underscore
            features['nb_underscore'] = url.count('_')
            
            # Feature: nb_tilde
            features['nb_tilde'] = url.count('~')
            
            # Feature: nb_percent
            features['nb_percent'] = url.count('%')
            
            # Feature: nb_slash
            features['nb_slash'] = url.count('/')
            
            # Feature: nb_star
            features['nb_star'] = url.count('*')
            
            # Feature: nb_colon
            features['nb_colon'] = url.count(':')
            
            # Feature: nb_comma
            features['nb_comma'] = url.count(',')
            
            # Feature: nb_semicolumn
            features['nb_semicolumn'] = url.count(';')
            
            # Feature: nb_dollar
            features['nb_dollar'] = url.count('$')
            
            # Feature: nb_space
            features['nb_space'] = url.count(' ')
            
            # Feature: nb_www
            features['nb_www'] = 1 if 'www' in domain.lower() else 0
            
            # Feature: nb_com
            features['nb_com'] = 1 if '.com' in url.lower() else 0
            
            # Feature: nb_dslash
            features['nb_dslash'] = url.count('//')
            
            # Feature: http_in_path
            features['http_in_path'] = 1 if 'http' in path.lower() else 0
            
            # Feature: https_token
            features['https_token'] = 1 if parsed_url.scheme == 'https' else 0
            
            # Feature: ratio_digits_url
            digits_count = sum(c.isdigit() for c in url)
            features['ratio_digits_url'] = digits_count / len(url) if len(url) > 0 else 0
            
            # Feature: ratio_digits_host
            host_digits_count = sum(c.isdigit() for c in domain)
            features['ratio_digits_host'] = host_digits_count / len(domain) if len(domain) > 0 else 0
            
            # Feature: punycode
            features['punycode'] = 1 if 'xn--' in domain.lower() else 0
            
            # Feature: port
            features['port'] = 1 if ':' in domain else 0
            
            # Feature: tld_in_path
            tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int']
            features['tld_in_path'] = 1 if any(tld in path.lower() for tld in tlds) else 0
            
            # Feature: tld_in_subdomain
            features['tld_in_subdomain'] = 1 if any(tld in ext.subdomain.lower() for tld in tlds) else 0
            
            # Feature: abnormal_subdomain
            features['abnormal_subdomain'] = 1 if len(ext.subdomain) > 20 else 0
            
            # Feature: nb_subdomains
            features['nb_subdomains'] = domain.count('.') + 1
            
            # Feature: prefix_suffix
            features['prefix_suffix'] = 1 if '-' in domain_name else 0
            
            # Feature: random_domain
            # This is a complex feature, we'll simplify
            features['random_domain'] = 0
            
            # Feature: shortening_service
            shortening_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'ow.ly', 'rebrand.ly']
            features['shortening_service'] = 1 if any(service in domain.lower() for service in shortening_services) else 0
            
            # Feature: path_extension
            common_extensions = ['.html', '.php', '.asp', '.aspx', '.jsp', '.js', '.css']
            features['path_extension'] = 1 if any(ext in path.lower() for ext in common_extensions) else 0
            
            # Feature: nb_redirection
            features['nb_redirection'] = self._count_redirects(url)
            
            # Feature: nb_external_redirection
            # This requires content analysis, we'll set a default
            features['nb_external_redirection'] = 0
            
            # Feature: length_words_raw
            words = re.findall(r'\w+', url)
            features['length_words_raw'] = len(words)
            
            # Feature: char_repeat
            features['char_repeat'] = self._count_repeated_chars(url)
            
            # Feature: shortest_words_raw
            features['shortest_words_raw'] = min([len(word) for word in words]) if words else 0
            
            # Feature: shortest_word_host
            host_words = re.findall(r'\w+', domain)
            features['shortest_word_host'] = min([len(word) for word in host_words]) if host_words else 0
            
            # Feature: shortest_word_path
            path_words = re.findall(r'\w+', path)
            features['shortest_word_path'] = min([len(word) for word in path_words]) if path_words else 0
            
            # Feature: longest_words_raw
            features['longest_words_raw'] = max([len(word) for word in words]) if words else 0
            
            # Feature: longest_word_host
            features['longest_word_host'] = max([len(word) for word in host_words]) if host_words else 0
            
            # Feature: longest_word_path
            features['longest_word_path'] = max([len(word) for word in path_words]) if path_words else 0
            
            # Feature: avg_words_raw
            features['avg_words_raw'] = sum([len(word) for word in words]) / len(words) if words else 0
            
            # Feature: avg_word_host
            features['avg_word_host'] = sum([len(word) for word in host_words]) / len(host_words) if host_words else 0
            
            # Feature: avg_word_path
            features['avg_word_path'] = sum([len(word) for word in path_words]) / len(path_words) if path_words else 0
            
            # The remaining features require content analysis or external services
            # We'll set default values for them
            default_features = {
                'phish_hints': 0,
                'domain_in_brand': 0,
                'brand_in_subdomain': 0,
                'brand_in_path': 0,
                'suspecious_tld': 0,
                'statistical_report': 0,
                'nb_hyperlinks': 0,
                'ratio_intHyperlinks': 0,
                'ratio_extHyperlinks': 0,
                'ratio_nullHyperlinks': 0,
                'nb_extCSS': 0,
                'ratio_intRedirection': 0,
                'ratio_extRedirection': 0,
                'ratio_intErrors': 0,
                'ratio_extErrors': 0,
                'login_form': 0,
                'external_favicon': 0,
                'links_in_tags': 0,
                'submit_email': 0,
                'ratio_intMedia': 0,
                'ratio_extMedia': 0,
                'sfh': 0,
                'iframe': 0,
                'popup_window': 0,
                'safe_anchor': 0,
                'onmouseover': 0,
                'right_clic': 0,
                'empty_title': 0,
                'domain_in_title': 0,
                'domain_with_copyright': 0,
                'whois_registered_domain': 0,
                'domain_registration_length': 0,
                'domain_age': 0,
                'web_traffic': 0,
                'dns_record': 0,
                'google_index': 0,
                'page_rank': 0
            }
            
            # Update features with default values
            features.update(default_features)
            
            # Try to get some content-based features if possible
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Feature: nb_hyperlinks
                    links = soup.find_all('a')
                    features['nb_hyperlinks'] = len(links)
                    
                    # Feature: login_form
                    forms = soup.find_all('form')
                    password_inputs = soup.find_all('input', {'type': 'password'})
                    features['login_form'] = 1 if forms and password_inputs else 0
                    
                    # Feature: iframe
                    iframes = soup.find_all('iframe')
                    features['iframe'] = 1 if iframes else 0
                    
                    # Feature: popup_window
                    popup_js = ['window.open', 'popup', 'alert(']
                    scripts = soup.find_all('script')
                    script_text = ' '.join([script.text for script in scripts])
                    features['popup_window'] = 1 if any(js in script_text for js in popup_js) else 0
                    
                    # Feature: onmouseover
                    onmouseover_elements = soup.find_all(attrs={"onmouseover": True})
                    features['onmouseover'] = 1 if onmouseover_elements else 0
                    
                    # Feature: right_clic
                    right_click_disabled = 'oncontextmenu="return false"' in response.text
                    features['right_clic'] = 0 if right_click_disabled else 1
                    
                    # Feature: empty_title
                    title = soup.find('title')
                    features['empty_title'] = 0 if title and title.text.strip() else 1
                    
                    # Feature: domain_in_title
                    features['domain_in_title'] = 1 if title and domain_name.lower() in title.text.lower() else 0
            except:
                pass
            
            # Try to get DNS record
            try:
                socket.gethostbyname(domain)
                features['dns_record'] = 1
            except:
                features['dns_record'] = 0
            
            # Try to get domain age
            try:
                domain_info = whois.whois(domain_name)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        creation_date = domain_info.creation_date[0]
                    else:
                        creation_date = domain_info.creation_date
                    
                    age_days = (datetime.now() - creation_date).days
                    features['domain_age'] = age_days
                    features['whois_registered_domain'] = 1
                else:
                    features['domain_age'] = -1
                    features['whois_registered_domain'] = 0
            except:
                features['domain_age'] = -1
                features['whois_registered_domain'] = 0
            
            return pd.DataFrame([features])
        
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {e}")
            # Return default features
            default_features = {
                'length_url': 0, 'length_hostname': 0, 'ip': 0, 'nb_dots': 0,
                'nb_hyphens': 0, 'nb_at': 0, 'nb_qm': 0, 'nb_and': 0,
                'nb_or': 0, 'nb_eq': 0, 'nb_underscore': 0, 'nb_tilde': 0,
                'nb_percent': 0, 'nb_slash': 0, 'nb_star': 0, 'nb_colon': 0,
                'nb_comma': 0, 'nb_semicolumn': 0, 'nb_dollar': 0, 'nb_space': 0,
                'nb_www': 0, 'nb_com': 0, 'nb_dslash': 0, 'http_in_path': 0,
                'https_token': 0, 'ratio_digits_url': 0, 'ratio_digits_host': 0,
                'punycode': 0, 'port': 0, 'tld_in_path': 0, 'tld_in_subdomain': 0,
                'abnormal_subdomain': 0, 'nb_subdomains': 0, 'prefix_suffix': 0,
                'random_domain': 0, 'shortening_service': 0, 'path_extension': 0,
                'nb_redirection': 0, 'nb_external_redirection': 0, 'length_words_raw': 0,
                'char_repeat': 0, 'shortest_words_raw': 0, 'shortest_word_host': 0,
                'shortest_word_path': 0, 'longest_words_raw': 0, 'longest_word_host': 0,
                'longest_word_path': 0, 'avg_words_raw': 0, 'avg_word_host': 0,
                'avg_word_path': 0, 'phish_hints': 0, 'domain_in_brand': 0,
                'brand_in_subdomain': 0, 'brand_in_path': 0, 'suspecious_tld': 0,
                'statistical_report': 0, 'nb_hyperlinks': 0, 'ratio_intHyperlinks': 0,
                'ratio_extHyperlinks': 0, 'ratio_nullHyperlinks': 0, 'nb_extCSS': 0,
                'ratio_intRedirection': 0, 'ratio_extRedirection': 0, 'ratio_intErrors': 0,
                'ratio_extErrors': 0, 'login_form': 0, 'external_favicon': 0,
                'links_in_tags': 0, 'submit_email': 0, 'ratio_intMedia': 0,
                'ratio_extMedia': 0, 'sfh': 0, 'iframe': 0, 'popup_window': 0,
                'safe_anchor': 0, 'onmouseover': 0, 'right_clic': 0, 'empty_title': 0,
                'domain_in_title': 0, 'domain_with_copyright': 0, 'whois_registered_domain': 0,
                'domain_registration_length': 0, 'domain_age': 0, 'web_traffic': 0,
                'dns_record': 0, 'google_index': 0, 'page_rank': 0
            }
            return pd.DataFrame([default_features])
    
    def _has_ip_address(self, domain):
        """Check if domain contains an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, domain))
    
    def _count_redirects(self, url, max_redirects=5):
        """Count the number of redirects for a URL"""
        try:
            response = requests.get(url, allow_redirects=True, timeout=3)
            return len(response.history) if response.history else 0
        except:
            return 0
    
    def _count_repeated_chars(self, text):
        """Count the number of repeated characters in a string"""
        if not text:
            return 0
        
        count = 0
        for i in range(len(text) - 1):
            if text[i] == text[i+1]:
                count += 1
        return count
    
    def predict(self, url):
        """Predict if a URL is phishing or legitimate"""
        if not self.model:
            logger.error("Model not loaded. Cannot make prediction.")
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'features': {},
                'phishing_indicators': []
            }
        
        try:
            # Extract features
            features_df = self.extract_features_from_url(url)
            
            # Store original features for return
            original_features = features_df.iloc[0].to_dict()
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            
            # Get probability scores
            proba = self.model.predict_proba(features_scaled)[0]
            confidence = proba[1] if prediction else 1 - proba[1]
            
            # Identify phishing indicators
            phishing_indicators = self._get_phishing_indicators(original_features)
            
            return {
                'is_phishing': bool(prediction),
                'confidence': float(confidence),
                'features': original_features,
                'phishing_indicators': phishing_indicators
            }
        
        except Exception as e:
            logger.error(f"Error making prediction for URL {url}: {e}")
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'features': {},
                'phishing_indicators': []
            }
    
    def _get_phishing_indicators(self, features):
        """Identify features that indicate phishing based on patterns"""
        indicators = []
        
        for feature, pattern in self.phishing_patterns.items():
            if feature not in features:
                continue
                
            value = features[feature]
            phish_mean = pattern['phish_mean']
            phish_std = pattern['phish_std']
            legit_mean = pattern['legit_mean']
            legit_std = pattern['legit_std']
            importance = pattern['importance']
            
            # Check if the feature value is closer to phishing mean than legitimate mean
            phish_distance = abs(value - phish_mean)
            legit_distance = abs(value - legit_mean)
            
            if phish_distance < legit_distance:
                # Calculate a score based on how close it is to phishing mean
                score = 1 - (phish_distance / (phish_std * 3 if phish_std > 0 else 1))
                score = max(0, min(1, score))  # Clamp between 0 and 1
                
                # Only include significant indicators
                if score > 0.6 and importance > 0.01:
                    indicators.append({
                        'feature': feature,
                        'value': value,
                        'score': score,
                        'importance': importance
                    })
        
        # Sort by importance * score
        indicators.sort(key=lambda x: x['importance'] * x['score'], reverse=True)
        
        # Return top 10 indicators
        return indicators[:10]

# Create an instance of the enhanced predictor
enhanced_predictor = EnhancedPhishingPredictor()

def predict_url(url):
    """Function to predict if a URL is phishing or legitimate"""
    result = enhanced_predictor.predict(url)
    
    # Format the result to match the expected output format
    phishing_indicators = result['phishing_indicators']
    
    # Create feature risks based on indicators
    feature_risks = {}
    for feature, value in result['features'].items():
        # Check if this feature is in the indicators
        indicator = next((i for i in phishing_indicators if i['feature'] == feature), None)
        
        if indicator:
            risk_score = indicator['score']
            if risk_score > 0.8:
                risk = 'high'
            elif risk_score > 0.6:
                risk = 'medium'
            else:
                risk = 'low'
        else:
            risk = 'low'
        
        feature_risks[feature] = {
            'value': value,
            'risk': risk
        }
    
    # Calculate overall risk score (0-10)
    risk_score = result['confidence'] * 10
    
    # Determine if suspicious (medium risk)
    is_suspicious = False
    if not result['is_phishing'] and risk_score > 3.0:
        is_suspicious = True
    
    return {
        'is_phishing': result['is_phishing'],
        'is_suspicious': is_suspicious,
        'risk_score': round(float(risk_score), 1),
        'features': feature_risks,
        'phishing_indicators': [
            {
                'feature': i['feature'],
                'value': i['value'],
                'importance': round(i['importance'] * 100, 2)
            } for i in phishing_indicators
        ]
    }