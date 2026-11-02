import mysql.connector
from config import DB_CONFIG

try:
    print("Connecting to MySQL database...")
    connection = mysql.connector.connect(**DB_CONFIG)
    
    if connection.is_connected():
        cursor = connection.cursor()
        
        # Check users table structure
        print("\nChecking users table structure:")
        cursor.execute("DESCRIBE users;")
        columns = cursor.fetchall()
        for column in columns:
            print(column)
        
        # Check existing users
        print("\nExisting users in the database:")
        cursor.execute("SELECT id, username, email, is_admin FROM users;")
        users = cursor.fetchall()
        if users:
            for user in users:
                print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Is Admin: {user[3]}")
        else:
            print("No users found in the database.")
            
except Exception as e:
    print(f"Error: {e}")
    
finally:
    if 'connection' in locals() and connection.is_connected():
        cursor.close()
        connection.close()
        print("\nMySQL connection is closed")