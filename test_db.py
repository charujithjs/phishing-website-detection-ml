import mysql.connector
from config import DB_CONFIG

try:
    print("Attempting to connect to MySQL database...")
    print(f"Connection parameters: {DB_CONFIG}")
    
    connection = mysql.connector.connect(**DB_CONFIG)
    
    if connection.is_connected():
        db_info = connection.get_server_info()
        print(f"Connected to MySQL Server version {db_info}")
        
        cursor = connection.cursor()
        cursor.execute("select database();")
        record = cursor.fetchone()
        print(f"Connected to database: {record[0]}")
        
        print("Testing database tables...")
        cursor.execute("SHOW TABLES;")
        tables = cursor.fetchall()
        print(f"Tables in database: {tables}")
        
except Exception as e:
    print(f"Error connecting to MySQL database: {e}")
    
finally:
    if 'connection' in locals() and connection.is_connected():
        cursor.close()
        connection.close()
        print("MySQL connection is closed")