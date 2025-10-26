import os
import urllib.parse
from sqlalchemy import create_engine, text

print("--- Starting Database Connection Test ---")

# Récupère la chaîne de connexion depuis les variables d'environnement
connection_string = os.environ.get('AZURE_SQL_CONNECTIONSTRING')

if not connection_string:
    print("FATAL ERROR: AZURE_SQL_CONNECTIONSTRING environment variable not found.")
else:
    try:
        print("Connection String found. Attempting to create engine...")
        
        quoted_conn_str = urllib.parse.quote_plus(connection_string)
        
        engine = create_engine(
            f'mssql+pyodbc:///?odbc_connect={quoted_conn_str}&driver=ODBC+Driver+17+for+SQL+Server',
            pool_timeout=30  # Augmentation du timeout pour être sûr
        )
        
        print("Engine created. Attempting to connect...")
        
        # Tente une connexion et une requête simple
        with engine.connect() as conn:
            print("Connection successful! Attempting to execute a simple query...")
            result = conn.execute(text("SELECT @@VERSION;")).scalar()
            print(f"SUCCESS! SQL Server Version: {result}")

    except Exception as e:
        print(f"CRITICAL ERROR DURING CONNECTION TEST: {e}")

print("--- End of Database Connection Test ---")