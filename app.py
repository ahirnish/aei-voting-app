# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os, datetime, json
import firebase_admin
from firebase_admin import credentials, auth
from werkzeug.security import generate_password_hash, check_password_hash


# Read database credentials from environment variables
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT')
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# Create connection string
DB_URI = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
# Use the connection string
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.context_processor
def inject_now():
    return {'now': datetime.datetime.now()}


# Option 1: Use environment variable containing the entire JSON
firebase_credentials_json = os.environ.get('FIREBASE_CREDENTIALS')
if firebase_credentials_json:
    # Parse the JSON string into a dictionary
    cred_dict = json.loads(firebase_credentials_json)
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred)
else:
    # Fallback for local development
    cred = credentials.Certificate('path/to/local/serviceAccountKey.json')
    firebase_admin.initialize_app(cred)

# Initialize Firebase Admin SDK (server-side)
# Replace 'path/to/serviceAccountKey.json' with your actual path
# cred = credentials.Certificate('voting-app-aei-firebase-adminsdk-fbsvc-3c56a79e4c.json')
# firebase_admin.initialize_app(cred)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    firebase_uid = db.Column(db.String(128), unique=True, nullable=True)
    has_voted = db.Column(db.Boolean, default=False)
    voted_for = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=True)
    
    def __repr__(self):
        return f'<User {self.phone_number}>'

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    def __repr__(self):
        return f'<Admin {self.username}>'

class VotingWindow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<VotingWindow {self.start_time} to {self.end_time}>'
    
    def is_open(self):
        if not self.is_active:
            return False
        
        now = datetime.datetime.now()
        
        # If times are not set, check only the active flag
        if not self.start_time or not self.end_time:
            return self.is_active
            
        # Check if current time is within the window
        return self.start_time <= now <= self.end_time

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    info = db.Column(db.Text, nullable=True)
    votes = db.Column(db.Integer, default=0)
    voters = db.relationship('User', backref='voted_candidate', lazy=True)
    
    def __repr__(self):
        return f'<Candidate {self.name}>'

# Create the database and tables
with app.app_context():
    db.create_all()
    
    # Add sample candidates if none exist
    if not Candidate.query.first():
        candidates = [
            Candidate(name="Alice Smith", info="Environmental policy advocate"),
            Candidate(name="Bob Johnson", info="Economic development expert"),
            Candidate(name="Carol Williams", info="Education reform specialist")
        ]
        db.session.add_all(candidates)
        db.session.commit()
    
    # Add admin account if it doesn't exist
    if not Admin.query.filter_by(username="admin").first():
        admin = Admin(
            username="admin",
            password=generate_password_hash("securepassword123")
        )
        db.session.add(admin)
        db.session.commit()
        
    # Create default voting window if it doesn't exist
    if not VotingWindow.query.first():
        # Default window - inactive, no dates set
        voting_window = VotingWindow(
            is_active=False,
            start_time=None,
            end_time=None
        )
        db.session.add(voting_window)
        db.session.commit()

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin login decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Check if voting is open
def voting_open_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        voting_window = VotingWindow.query.first()
        if not voting_window or not voting_window.is_open():
            flash('Voting is currently closed', 'warning')
            return redirect(url_for('candidates'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('candidates'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/check_phone', methods=['POST'])
def check_phone():
    phone_number = request.json.get('phoneNumber')
    
    if not phone_number:
        return jsonify({'success': False, 'message': 'Phone number is required'}), 400
    
    # Check if user exists in our database
    user = User.query.filter_by(phone_number=phone_number).first()
    
    if user:
        return jsonify({'success': True, 'exists': True})
    else:
        return jsonify({'success': True, 'exists': False, 'message': 'You are not a registered member.'})

@app.route('/verify_token', methods=['POST'])
def verify_token():
    id_token = request.json.get('idToken')
    
    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)
        firebase_uid = decoded_token['uid']
        phone_number = decoded_token.get('phone_number')
        print(f'phone_number: {phone_number}')
        
        if not phone_number:
            return jsonify({'success': False, 'message': 'No phone number found in token'}), 400
        
        # Check if user exists in our database
        user = User.query.filter_by(phone_number=phone_number).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'You are not a registered member. Access denied.'}), 403
        
        # Update Firebase UID if it changed
        if user.firebase_uid != firebase_uid:
            user.firebase_uid = firebase_uid
            db.session.commit()
        
        # Set session
        session['user_id'] = user.id
        session['phone_number'] = phone_number
        
        return jsonify({'success': True, 'redirect': url_for('candidates')})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 401


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('phone_number', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/candidates')
@login_required
def candidates():
    candidates = Candidate.query.all()
    user = User.query.get(session['user_id'])
    selected_candidate = None
    
    if user.has_voted and user.voted_for:
        selected_candidate = user.voted_for
    
    voting_window = VotingWindow.query.first()
    voting_open = voting_window and voting_window.is_open()
    
    # Format the start and end times for display
    start_time_str = voting_window.start_time.strftime("%b %d, %Y at %I:%M %p") if voting_window and voting_window.start_time else "Not set"
    end_time_str = voting_window.end_time.strftime("%b %d, %Y at %I:%M %p") if voting_window and voting_window.end_time else "Not set"
    
    return render_template('candidates.html', 
                          candidates=candidates, 
                          has_voted=user.has_voted, 
                          selected_candidate=selected_candidate,
                          phone_number=session.get('phone_number'),
                          voting_open=voting_open,
                          start_time=start_time_str,
                          end_time=end_time_str)

@app.route('/vote/<int:candidate_id>', methods=['POST'])
@login_required
@voting_open_required
def vote(candidate_id):
    user = User.query.get(session['user_id'])
    
    if user.has_voted:
        flash('You have already voted', 'warning')
        return redirect(url_for('candidates'))
    
    candidate = Candidate.query.get_or_404(candidate_id)
    candidate.votes += 1
    user.has_voted = True
    user.voted_for = candidate.id
    
    db.session.commit()
    
    flash(f'Your vote for {candidate.name} has been recorded. Thank you!', 'success')
    return redirect(url_for('vote_confirmation', candidate_id=candidate.id))

@app.route('/vote_confirmation/<int:candidate_id>')
@login_required
def vote_confirmation(candidate_id):
    candidate = Candidate.query.get_or_404(candidate_id)
    return render_template('vote_confirmation.html', candidate=candidate)
    
@app.route('/check_voting_status')
@admin_required
def check_voting_status():
    total_users = User.query.count()
    voted_users = User.query.filter_by(has_voted=True).count()
    pending_users = total_users - voted_users
    
    vote_percentage = (voted_users / total_users * 100) if total_users > 0 else 0
    
    candidate_stats = []
    candidates = Candidate.query.all()
    for candidate in candidates:
        candidate_stats.append({
            'name': candidate.name,
            'votes': candidate.votes
        })
    
    voting_window = VotingWindow.query.first()
    
    return render_template('voting_status.html', 
                          total_users=total_users,
                          voted_users=voted_users,
                          pending_users=pending_users,
                          vote_percentage=vote_percentage,
                          candidate_stats=candidate_stats,
                          voting_window=voting_window)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        
        if not admin or not check_password_hash(admin.password, password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('admin_login'))
        
        session['admin_id'] = admin.id
        session['admin_username'] = admin.username
        flash('Admin login successful', 'success')
        return redirect(url_for('check_voting_status'))
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    flash('You have been logged out from admin account', 'info')
    return redirect(url_for('admin_login'))

@app.route('/results')
@admin_required
def results():
    total_users = User.query.count()
    voted_users = User.query.filter_by(has_voted=True).count()
    pending_users = total_users - voted_users
    
    candidates = Candidate.query.order_by(Candidate.votes.desc()).all()
    total_votes = sum(c.votes for c in candidates)
    
    voting_window = VotingWindow.query.first()
    
    return render_template('results.html', 
                         candidates=candidates, 
                         total_votes=total_votes,
                         voted_users=voted_users,
                         pending_users=pending_users,
                         voting_window=voting_window)

# Add these routes to app.py

@app.route('/admin/manage_voting', methods=['GET'])
@admin_required
def manage_voting():
    voting_window = VotingWindow.query.first()
    
    # Format dates for display in the form
    start_time_str = voting_window.start_time.strftime("%Y-%m-%dT%H:%M") if voting_window.start_time else ""
    end_time_str = voting_window.end_time.strftime("%Y-%m-%dT%H:%M") if voting_window.end_time else ""
    
    return render_template('manage_voting.html', 
                          voting_window=voting_window,
                          start_time=start_time_str,
                          end_time=end_time_str)

@app.route('/admin/update_voting_window', methods=['POST'])
@admin_required
def update_voting_window():
    voting_window = VotingWindow.query.first()
    
    # Get form data
    is_active = 'is_active' in request.form
    start_time_str = request.form.get('start_time', '')
    end_time_str = request.form.get('end_time', '')
    
    # Parse dates if provided
    start_time = datetime.datetime.fromisoformat(start_time_str) if start_time_str else None
    end_time = datetime.datetime.fromisoformat(end_time_str) if end_time_str else None
    
    # Update voting window
    voting_window.is_active = is_active
    voting_window.start_time = start_time
    voting_window.end_time = end_time
    
    db.session.commit()
    
    flash('Voting window updated successfully', 'success')
    return redirect(url_for('manage_voting'))

@app.route('/admin/open_voting')
@admin_required
def open_voting():
    voting_window = VotingWindow.query.first()
    voting_window.is_active = True
    voting_window.end_time = None
    db.session.commit()
    
    flash('Voting is now open', 'success')
    return redirect(url_for('check_voting_status'))

@app.route('/admin/close_voting')
@admin_required
def close_voting():
    voting_window = VotingWindow.query.first()
    voting_window.is_active = False
    db.session.commit()
    
    flash('Voting is now closed', 'success')
    return redirect(url_for('check_voting_status'))

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/offline.html')
def offline():
    return send_from_directory('static', 'offline.html')

@app.route('/service-worker.js')
def service_worker():
    return send_from_directory('static', 'service-worker.js')

if __name__ == '__main__':
    # app.run(debug=True)
    app.run(host='0.0.0.0', port=5000, debug=False)
