from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "secret123"

# ----------------------------
# MongoDB setup
# ----------------------------
MONGO_URI = "mongodb://127.0.0.1:27017/"
client = MongoClient(MONGO_URI)

db = client["waste_app1"]
users_col = db["users"]
requests_col = db["requests"]
facilities_col = db["facilities"]
events_col = db["events"]
marketplace_col = db["marketplace"]
fines_col = db["fines"]
vehicles_col = db["vehicles"]


UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ----------------------------
# Helpers
# ----------------------------
def current_user():
    if "user_id" in session:
        return users_col.find_one({"_id": ObjectId(session["user_id"])})
    return None

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in roles:
                return render_template("error_403.html")
            return f(*args, **kwargs)
        return wrapper
    return decorator


def serialize_doc(doc):
    """Convert ObjectId to string for templates"""
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    # Ensure is_head exists
    if "is_head" not in doc:
        doc["is_head"] = False
    return doc



def serialize_list(docs):
    return [serialize_doc(d) for d in docs]

# ----------------------------
# Home
# ----------------------------
@app.route("/")
def home():
    return render_template("index.html", user=current_user())

# ----------------------------
# Authentication
# ----------------------------
# ----------------------------
# Registration with debug
# ----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "citizen")
        address = request.form.get("address", "")

        if not name or not username or not password:
            flash("Please fill all required fields!", "danger")
            return redirect(url_for("register"))

        existing_user = users_col.find_one({"username": username})
        if existing_user:
            flash("Username already exists", "danger")
            print("DEBUG: Attempted to register with existing username:", username)
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        user_doc = {
            "name": name,
            "username": username,
            "password": hashed_password,
            "role": role,
            "address": address,
            "completed": False,
            "points": 0,
            "badges": [],
            "is_head": False,
            "fines": 0,
            "suspended": False
        }

        try:
            result = users_col.insert_one(user_doc)
            print("DEBUG: Registered user_id:", result.inserted_id)
            print("DEBUG: User in DB now:", users_col.find_one({"_id": result.inserted_id}))
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print("DEBUG: Registration error:", e)
            flash(f"Registration failed: {e}", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

# ----------------------------
# Login with debug
# ----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Please enter both username and password!", "danger")
            return redirect(url_for("login"))

        user = users_col.find_one({"username": username})
        print("DEBUG: User fetched from DB:", user)

        if user:
            if check_password_hash(user["password"], password):
                session["user_id"] = str(user["_id"])
                flash("Welcome back!", "success")
                print("DEBUG: Login successful for:", username)

                # Redirect based on role
                if user["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                elif user.get("is_head") and user["role"] in ["worker", "worker_head"]:
                    return redirect(url_for("worker_head_dashboard"))
                elif user["role"] == "worker":
                    return redirect(url_for("worker_dashboard"))
                else:
                    return redirect(url_for("citizen_dashboard"))
            else:
                flash("Invalid credentials (wrong password)", "danger")
                print("DEBUG: Wrong password for:", username)
        else:
            flash("Invalid credentials (user not found)", "danger")
            print("DEBUG: No user found with username:", username)

        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


# ----------------------------
# Admin Dashboard
# ----------------------------
@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    user = current_user()
    if user["role"] != "admin":
        return render_template("error_403.html")

    all_users = []
    for u in users_col.find():
        u_doc = serialize_doc(u)
        all_users.append({
            **u_doc,
            "can_promote": u_doc["role"] == "worker" and not u_doc["is_head"],
            "can_demote": u_doc["role"] == "worker" and u_doc["is_head"]
        })

    # All requests for admin dashboard
    all_requests = []
    common_requests_map = []
    for r in requests_col.find():
        r_doc = serialize_doc(r)
        user_doc = users_col.find_one({"_id": r["user_id"]})
        r_doc["user_name"] = user_doc["name"] if user_doc else "Unknown"
        r_doc["status"] = r_doc.get("status", "").lower()
        all_requests.append(r_doc)

        if r_doc.get("type") == "common" and r_doc.get("lat") and r_doc.get("lng"):
            common_requests_map.append({
                "place": r_doc.get("common_place"),
                "lat": r_doc["lat"],
                "lng": r_doc["lng"],
                "image": r_doc.get("image") or ""
            })

    return render_template(
        "dashboard_admin.html",
        user=user,
        all_users=all_users,
        all_requests=all_requests,
        common_requests_map=common_requests_map
    )


# ----------------------------
# Approve / Reject Request
# ----------------------------
@app.route('/update_request/<request_id>/<action>')
@login_required
def update_request(request_id, action):
    user = current_user()
    if user.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    status = "approved" if action.lower() == "approve" else "rejected"
    requests_col.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": status}}
    )
    flash(f"Request {status}!", "success")
    return redirect(url_for('admin_dashboard'))


# ----------------------------
# Promote to Head
# ----------------------------
@app.route("/promote_to_head/<user_id>")
@login_required
def promote_to_head(user_id):
    user = current_user()
    if user["role"] != "admin":
        return render_template("error_403.html")

    users_col.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": "worker", "is_head": True}}
    )
    flash("Worker promoted to Worker Head!", "success")
    return redirect(url_for("admin_dashboard"))

# ----------------------------
# Demote Head to Worker
# ----------------------------
@app.route("/demote_head/<user_id>")
@login_required
def demote_head(user_id):
    user = current_user()
    if user["role"] != "admin":
        return render_template("error_403.html")

    users_col.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": "worker", "is_head": False}}
    )
    flash("Worker Head demoted to Worker!", "success")
    return redirect(url_for("admin_dashboard"))

# ----------------------------
# Update User Role (generic)
# ----------------------------
@app.route('/update_role/<user_id>/<new_role>')
@login_required
def update_role(user_id, new_role):
    user = current_user()
    if user.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    valid_roles = ["citizen", "worker", "worker_head"]
    if new_role not in valid_roles:
        flash("Invalid role", "danger")
        return redirect(url_for('admin_dashboard'))

    users_col.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role, "is_head": new_role == "worker_head"}}
    )
    flash(f"User role updated to {new_role}!", "success")
    return redirect(url_for('admin_dashboard'))


# ----------------------------
# Assign Head Placeholder
# ----------------------------
@app.route("/assign_head/<request_id>")
@login_required
def assign_head(request_id):
    user = current_user()
    if user["role"] != "admin":
        return render_template("error_403.html")
    # Placeholder: You can implement assignment page later
    flash("Assignment page coming soon!", "info")
    return redirect(url_for("admin_dashboard"))

# ----------------------------
# Citizen Dashboard
# ----------------------------
@app.route("/citizen_dashboard", methods=["GET", "POST"])
@login_required
def citizen_dashboard():
    user = current_user()
    if user["role"] != "citizen":
        return render_template("error_403.html")

    # ----------------------------
    # Restrict access until training completed
    # ----------------------------
    if not user.get("completed", False):
        flash("You must complete the training before accessing the dashboard.", "warning")
        return redirect(url_for("training_citizen"))

    if request.method == "POST":
        # --- Home collection ---
        if "collect_home" in request.form:
            requests_col.insert_one({
                "user_id": user["_id"],
                "type": "home",
                "address": user["address"],
                "status": "Pending",
                "timestamp": datetime.now()
            })
            flash("Home collection request submitted!", "success")

        # --- Common place collection ---
        elif "collect_common" in request.form:
            place = request.form.get("common_place")
            image = request.files.get("image")
            lat = request.form.get("lat")
            lng = request.form.get("lng")

            if not place or not image or not lat or not lng:
                flash("All fields are required for common place request.", "danger")
                return redirect(url_for("citizen_dashboard"))

            filename = image.filename
            image.save(os.path.join(UPLOAD_FOLDER, filename))

            requests_col.insert_one({
                "user_id": user["_id"],
                "type": "common",
                "common_place": place,
                "image": filename,
                "lat": float(lat),
                "lng": float(lng),
                "status": "Pending",
                "timestamp": datetime.now()
            })
            flash("Common place request submitted!", "success")

        return redirect(url_for("citizen_dashboard"))

    # Fetch all requests for this user
    requests_list = [serialize_doc(r) for r in requests_col.find({"user_id": user["_id"]})]
    top_users = list(users_col.find().sort("points", -1).limit(10))
    return render_template("dashboard_citizen.html", user=user, requests=requests_list, leaderboard=top_users)

# ----------------------------
# Training
# ----------------------------
@app.route("/training/citizen", methods=["GET", "POST"])
@login_required
def training_citizen():
    user = current_user()
    if user["role"] != "citizen":
        return render_template("error_403.html")

    if request.method == "POST":
        # Example quiz questions
        if request.form.get("q1") == "brown" and request.form.get("q2") == "vegetable":
            # Update user: completed training + points + badge
            users_col.update_one(
                {"_id": user["_id"]},
                {"$set": {"completed": True}, "$inc": {"points": 10}, "$push": {"badges": "Trained Citizen"}}
            )
            flash("Citizen training completed! Redirecting to dashboard...", "success")
            # Redirect to dashboard immediately
            return redirect(url_for("citizen_dashboard"))
        else:
            flash("Incorrect answers. Please try again.", "danger")
            return redirect(url_for("training_citizen"))

    return render_template("training_citizen.html", user=user)


# ----------------------------
# Worker Training
# ----------------------------
@app.route("/training_worker", methods=["GET", "POST"])
@login_required
@role_required(["worker"])
def training_worker():
    user = current_user()

    if request.method == "POST":
        # Simple example check of quiz answers
        correct = {
            "q1": "special_bin",
            "q2": "recycle_bin",
            "q3": "segregated"
        }

        passed = all(request.form.get(q) == ans for q, ans in correct.items())

        if passed:
            users_col.update_one(
                {"_id": user["_id"]},
                {"$set": {"completed": True}}
            )
            flash("Training completed! You can now access your dashboard.", "success")
            return redirect(url_for("dashboard_worker"))
        else:
            flash("Some answers are incorrect. Please try again.", "danger")

    # GET request or not completed
    return render_template("training_worker.html", completed=user.get("completed", False))

# ----------------------------
# Worker Dashboard
# ----------------------------
@app.route("/worker_dashboard")
@login_required
@role_required(["worker"])
def worker_dashboard():
    user = current_user()
    
    # Check if training is completed
    if not user.get("completed", False):
        return redirect(url_for("training_worker"))

    # Fetch tasks assigned to this worker
    tasks_list = serialize_list(
        requests_col.find({
            "worker_id": user["_id"],
            "status": {"$in": ["assigned", "submitted", "completed"]}
        }).sort("timestamp", 1)
    )

    return render_template("dashboard_worker.html", tasks=tasks_list, user=user)

# ----------------------------
# Worker Submit Task
# ----------------------------
@app.route("/worker_submit/<task_id>", methods=["POST"])
@login_required
@role_required(["worker"])
def worker_submit(task_id):
    user = current_user()

    # Force ObjectId for query
    task = requests_col.find_one({
        "_id": ObjectId(task_id),
        "worker_id": ObjectId(user["_id"]),   # ✅ ensure type match
        "status": "assigned"
    })

    if not task:
        flash("Work not assigned to you or already submitted.", "danger")
        # Debug helper
        found_task = requests_col.find_one({"_id": ObjectId(task_id)})
        print("DEBUG - Task worker_id:", found_task.get("worker_id"), 
              "Current user:", user["_id"], 
              "Status:", found_task.get("status"))
        return redirect(url_for("worker_dashboard"))

    # Handle uploaded image
    if "image" not in request.files:
        flash("No image uploaded!", "danger")
        return redirect(url_for("worker_dashboard"))

    file = request.files["image"]
    if file.filename == "":
        flash("No image selected!", "danger")
        return redirect(url_for("worker_dashboard"))

    filename = secure_filename(file.filename)
    filepath = os.path.join("static/uploads", filename)
    file.save(filepath)

    # Update task status to submitted
    requests_col.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {
            "status": "submitted",
            "submission_image": filename
        }}
    )

    flash("Work submitted successfully!", "success")
    return redirect(url_for("worker_dashboard"))


@app.route("/worker_complete/<task_id>")
@login_required
@role_required(["worker"])
def worker_complete(task_id):
    user = current_user()
    requests_col.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": "Completed"}})
    users_col.update_one({"_id": user["_id"]}, {"$inc": {"points": 5}, "$push": {"badges": "Task Completed"}})
    flash("Task completed!", "success")
    return redirect(url_for("worker_dashboard"))

# ----------------------------
# Worker Head Dashboard
# ----------------------------
@app.route("/worker_head_dashboard")
@login_required
@role_required(["worker", "worker_head"])
def worker_head_dashboard():
    user = current_user()
     # 🔹 Redirect if training not done
    if not user.get("completed"):
        return redirect(url_for("training_worker"))
    if not user.get("is_head"):
        return render_template("error_403.html")

    # Fetch all relevant requests:
    # 1. Approved but not yet assigned (to this or any head)
    # 2. Already assigned/submitted/completed under this head
    requests_list = serialize_list(
        requests_col.find({
            "$or": [
                {"status": "approved"},  # approved requests not yet assigned
                {"worker_head_id": user["_id"], "status": {"$in": ["assigned", "submitted", "completed"]}}
            ]
        }).sort("timestamp", 1)
    )

    # Fetch all workers (non-head) for assignment
    workers = serialize_list(users_col.find({"role": "worker", "is_head": False}))

    return render_template(
        "dashboard_worker_head.html",
        user=user,
        requests=requests_list,
        workers=workers
    )


# ----------------------------
# Assign Worker
# ----------------------------
@app.route("/assign_worker", methods=["POST"])
@login_required
@role_required(["worker_head"])  # Only worker heads can assign
def assign_worker():
    user = current_user()
    if not user.get("is_head"):
        return render_template("error_403.html")

    request_id = request.form["request_id"]
    worker_id = request.form["worker_id"]

    # Fetch the request
    req = requests_col.find_one({"_id": ObjectId(request_id)})
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("worker_head_dashboard"))

    # Only allow assigning if request is approved or not yet assigned
    if req.get("status") != "approved":
        flash("Cannot assign this request.", "danger")
        return redirect(url_for("worker_head_dashboard"))

    # Set worker_id and worker_head_id
    requests_col.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {
            "status": "assigned",
            "worker_id": ObjectId(worker_id),
            "worker_head_id": user["_id"]
        }}
    )

    flash("Worker assigned!", "success")
    return redirect(url_for("worker_head_dashboard"))


# ----------------------------
# Worker Head Marks Complete
# ----------------------------
@app.route("/worker_head_complete/<task_id>")
@login_required
@role_required(["worker_head"])  # Only worker heads can mark complete
def worker_head_complete(task_id):
    user = current_user()
    if not user.get("is_head"):
        return render_template("error_403.html")

    # Only tasks under this head and submitted
    task = requests_col.find_one({
        "_id": ObjectId(task_id),
        "worker_head_id": user["_id"],
        "status": "submitted"
    })

    if not task:
        flash("Task not found or not submitted yet.", "danger")
        return redirect(url_for("worker_head_dashboard"))

    # Mark as completed
    requests_col.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": {"status": "completed"}}
    )

    # Award points to the worker
    if task.get("worker_id"):
        users_col.update_one(
            {"_id": task["worker_id"]},
            {"$inc": {"points": 5}, "$push": {"badges": "Task Completed"}}
        )

    flash("Task marked as completed!", "success")
    return redirect(url_for("worker_head_dashboard"))

# ----------------------------
# Requests Map for Admin/Worker
# ----------------------------
@app.route("/requests_map")
@login_required
def requests_map():
    user = current_user()
    if user["role"] not in ["admin", "worker", "worker_head"]:
        return render_template("error_403.html")

    # Fetch only common place requests with coordinates
    requests_list = []
    for r in requests_col.find({"type": "common", "lat": {"$ne": None}, "lng": {"$ne": None}}):
        requests_list.append({
            "common_place": r.get("common_place"),
            "lat": r.get("lat"),
            "lng": r.get("lng"),
            "status": r.get("status"),
            "user_id": str(r.get("user_id")),
            "timestamp": r.get("timestamp").strftime("%Y-%m-%d %H:%M") if r.get("timestamp") else ""
        })
    return render_template("requests_map.html", requests=requests_list)


# ----------------------------
# Events
# ----------------------------
@app.route("/events", methods=["GET", "POST"])
@login_required
def events():
    user = current_user()
    if request.method == "POST" and user["role"] == "admin":
        title = request.form["title"]
        location = request.form["location"]
        events_col.insert_one({"title": title, "location": location, "date": datetime.now(), "participants": []})
        flash("Event created!", "success")
        return redirect(url_for("events"))

    all_events = serialize_list(events_col.find())
    return render_template("events.html", user=user, events=all_events)

@app.route("/join_event/<event_id>")
@login_required
def join_event(event_id):
    user = current_user()
    event = events_col.find_one({"_id": ObjectId(event_id)})
    if user["_id"] not in event.get("participants", []):
        events_col.update_one({"_id": ObjectId(event_id)}, {"$push": {"participants": user["_id"]}})
        users_col.update_one({"_id": user["_id"]}, {"$inc": {"points": 10}, "$push": {"badges": "Volunteer"}})
        flash("Joined event!", "success")
    else:
        flash("Already joined!", "info")
    return redirect(url_for("events"))

# ----------------------------
# Facilities
# ----------------------------
@app.route("/facilities")
def facilities():
    facs = serialize_list(facilities_col.find())
    return render_template("facilities.html", facilities=facs)

# ----------------------------
# Marketplace
# ----------------------------
@app.route("/marketplace")
@login_required
def marketplace():
    items = serialize_list(marketplace_col.find())
    return render_template("marketplace.html", user=current_user(), items=items)

@app.route("/buy/<item_id>")
@login_required
def buy_item(item_id):
    user = current_user()
    item = marketplace_col.find_one({"_id": ObjectId(item_id)})
    if item and user["points"] >= item.get("price_points", 0):
        users_col.update_one({"_id": user["_id"]}, {"$inc": {"points": -item["price_points"]}})
        flash(f"Purchased {item['item_name']}!", "success")
    else:
        flash("Not enough points!", "danger")
    return redirect(url_for("marketplace"))

# ----------------------------
# Vehicles (Tracking)
# ----------------------------
@app.route("/vehicles")
@login_required
@role_required(["admin"])
def vehicles():
    vehs = serialize_list(vehicles_col.find())
    return render_template("vehicles.html", vehicles=vehs)

@app.route("/vehicle_update/<vehicle_id>", methods=["POST"])
def vehicle_update(vehicle_id):
    lat = float(request.form["lat"])
    lng = float(request.form["lng"])
    vehicles_col.update_one(
        {"_id": ObjectId(vehicle_id)},
        {"$set": {"lat": lat, "lng": lng, "last_updated": datetime.now()}},
        upsert=True
    )
    return jsonify({"status": "ok"})

# ----------------------------
# Delete User
# ----------------------------
@app.route("/delete_user")
@login_required
def delete_user():
    return render_template("delete_user.html", user=current_user())

@app.route("/confirm_delete_user")
@login_required
def confirm_delete_user():
    user = current_user()
    users_col.delete_one({"_id": user["_id"]})
    requests_col.delete_many({"user_id": user["_id"]})
    session.clear()
    flash("Account deleted.", "success")
    return render_template("delete_success.html")

# ----------------------------
# Error Handlers
# ----------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error_403.html"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error_404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error_500.html"), 500

# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)