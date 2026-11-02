import mysql.connector
from config import DB_CONFIG
import database as db
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_user_registration():
    # Test user details
    test_username = "testuser123"
    test_password = "Test@123"
    test_email = "testuser123@example.com"
    
    # First, check if the test user already exists and delete if necessary
    connection = mysql.connector.connect(**DB_CONFIG)
    cursor = connection.cursor()
    
    try:
        # Delete test user if exists
        cursor.execute("DELETE FROM users WHERE username = %s", (test_username,))
        cursor.execute("DELETE FROM users WHERE email = %s", (test_email,))
        connection.commit()
        print(f"Cleaned up any existing test user data")
    except Exception as e:
        print(f"Error during cleanup: {e}")
    finally:
        cursor.close()
        connection.close()
    
    # Now try to create the user
    print(f"\nAttempting to create test user: {test_username}")
    user_id = db.create_user(test_username, test_password, test_email, is_admin=False)
    
    if user_id and user_id > 0:
        print(f"SUCCESS: User created with ID: {user_id}")
    else:
        print(f"FAILED: Could not create user. Return value: {user_id}")
    
    # Verify the user was created
    connection = mysql.connector.connect(**DB_CONFIG)
    cursor = connection.cursor()
    
    try:
        cursor.execute("SELECT id, username, email, is_admin FROM users WHERE username = %s", (test_username,))
        user = cursor.fetchone()
        
        if user:
            print(f"VERIFICATION: User found in database:")
            print(f"  ID: {user[0]}")
            print(f"  Username: {user[1]}")
            print(f"  Email: {user[2]}")
            print(f"  Is Admin: {user[3]}")
        else:
            print("VERIFICATION FAILED: User not found in database")
    except Exception as e:
        print(f"Error during verification: {e}")
    finally:
        cursor.close()
        connection.close()

if __name__ == "__main__":
    test_user_registration()