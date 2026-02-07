import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
