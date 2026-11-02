# Copy this file to config.py and fill in your own values.
# config.py is listed in .gitignore and must never be uploaded to GitHub.

# Database configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "your_mysql_username",
    "password": "your_mysql_password",
    "database": "phishingdetection"
}

# Secret key used to sign login sessions.
# Use a long random value. You can generate one with:
#   python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = "change-this-to-a-long-random-string"
