from pymongo import MongoClient
from werkzeug.security import generate_password_hash

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client['waste_app1']   # make sure this matches your app.py DB
users_collection = db['users']

def create_admin():
    print("=== Create Admin User ===")
    name = input("Enter admin name: ").strip()
    username = input("Enter admin username: ").strip()
    password = input("Enter admin password: ").strip()
    address = input("Enter admin address: ").strip()

    if users_collection.find_one({"username": username}):
        print("❌ Username already exists. Choose a different one.")
        return

    hashed_password = generate_password_hash(password)

    admin_user = {
        "name": name,
        "username": username,
        "password": hashed_password,
        "address": address,
        "role": "admin",
        "completed": True,
        "points": 0,
        "badges": [],
        "is_head": False
    }

    users_collection.insert_one(admin_user)
    print("✅ Admin created successfully!")

if __name__ == "__main__":
    create_admin()
