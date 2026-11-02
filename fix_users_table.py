import mysql.connector
from config import DB_CONFIG

try:
    print("Connecting to MySQL database...")
    connection = mysql.connector.connect(**DB_CONFIG)
    
    if connection.is_connected():
        cursor = connection.cursor()
        
        # Check if is_admin column exists
        cursor.execute("SHOW COLUMNS FROM users LIKE 'is_admin';")
        is_admin_exists = cursor.fetchone()
        
        if not is_admin_exists:
            print("Adding is_admin column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE;")
            connection.commit()
            print("is_admin column added successfully.")
        else:
            print("is_admin column already exists.")
            
        # Check updated table structure
        print("\nUpdated users table structure:")
        cursor.execute("DESCRIBE users;")
        columns = cursor.fetchall()
        for column in columns:
            print(column)
            
except Exception as e:
    print(f"Error: {e}")
    
finally:
    if 'connection' in locals() and connection.is_connected():
        cursor.close()
        connection.close()
        print("\nMySQL connection is closed")