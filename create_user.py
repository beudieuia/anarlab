# C:/anarlab/create_user.py
import pyodbc
from werkzeug.security import generate_password_hash

# --- IMPORTANT: Configure your DB connection here, just like in app.py ---
DB_SERVER = 'AHMED\SQLEXPRESS'
DB_NAME = 'MineralLabDB'
connection_string = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={DB_SERVER};DATABASE={DB_NAME};Trusted_Connection=yes;'

def create_user():
    """A command-line utility to create a new user."""
    try:
        conn = pyodbc.connect(connection_string, autocommit=True)
        cursor = conn.cursor()
        print("--- Create New AnarLab User ---")
        
        username = input("Enter username: ")
        password = input("Enter password: ")
        role = input("Enter role (e.g., admin, analyst): ")

        # Check if user already exists
        cursor.execute("SELECT COUNT(*) FROM Users WHERE Username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            print(f"Error: User '{username}' already exists.")
            return

        # Hash the password for security
        password_hash = generate_password_hash(password)

        # Insert the new user into the database
        cursor.execute(
            "INSERT INTO Users (Username, PasswordHash, Role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        
        print(f"\nUser '{username}' created successfully with role '{role}'.")
        conn.close()

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    create_user()