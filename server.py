from flask import Flask, request, jsonify, send_file, make_response
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from bson.errors import InvalidId
from dateutil import parser
import os   
from dotenv import load_dotenv
from functools import wraps
import pandas as pd
from io import BytesIO  
import pytz
from tzlocal import get_localzone
import io
import csv
from dateutil import parser
from werkzeug.utils import secure_filename


# Load environment variables
load_dotenv()

app = Flask(__name__)

# Add this CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:5173", "http://127.0.0.1:5173"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# MongoDB Configuration
# mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
mongo_uri = "mongodb+srv://virupaksh:Virupaksh%401234@cluster0.goirrab.mongodb.net/attendance_db?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(mongo_uri)
db = client[os.getenv('MONGO_DB_NAME', 'attendance_db')]


# Collections
users_collection = db.users
attendance_logs_collection = db.attendance_logs
leave_requests_collection = db.leave_requests
holidays_collection = db.holidays
system_settings_collection = db.system_settings
leave_policies_collection = db.leave_policies

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '5456e95f4a7102014229105eae27ec0812a265191f1e3bc6633452369a9bb5c5')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
TOKEN_EXPIRATION = timedelta(days=1)   # 1 day

# Get local timezone
LOCAL_TIMEZONE = get_localzone()

def get_current_time():
    """Returns current time in local system timezone with UTC offset"""
    now = datetime.now(LOCAL_TIMEZONE)
    return now.replace(tzinfo=LOCAL_TIMEZONE)

def initialize_database():
    # Create indexes
    users_collection.create_index([('email', 1)], unique=True)
    attendance_logs_collection.create_index([('user_id', 1), ('date', -1)])
    leave_requests_collection.create_index([('user_id', 1), ('status', 1)])
    
    # Create default admin if not exists
    if users_collection.count_documents({'email': 'admin@example.com'}) == 0:
        users_collection.insert_one({
            'username': 'Admin',
            'email': 'admin@example.com',
            'password': generate_password_hash('admin123'),
            'role': 'admin',
            'created_at': datetime.now(timezone.utc),
            'leave_balance': 20
        })
    
    # Insert sample holidays if collection is empty
    if holidays_collection.count_documents({}) == 0:
      holidays_collection.insert_many([
        {
            'name': 'New Year',
            'date': datetime(datetime.now().year, 1, 1, tzinfo=LOCAL_TIMEZONE)
        },
        {
            'name': 'Labor Day',
            'date': datetime(datetime.now().year, 5, 1, tzinfo=LOCAL_TIMEZONE)
        },
        {
            'name': 'Independence Day',
            'date': datetime(datetime.now().year, 7, 4, tzinfo=LOCAL_TIMEZONE)
        }
    ])

    
    # Set default work hours if not exists
    if not system_settings_collection.find_one({'key': 'work_hours'}):
        system_settings_collection.insert_one({
            'key': 'work_hours',
            'value': {
                'start_time': '09:00',
                'end_time': '17:00',
                'working_days': [1, 2, 3, 4, 5]  # Monday to Friday
            }
        })
    
    # Set default leave policy if not exists
    if not leave_policies_collection.find_one({'key': 'leave_policy'}):
        leave_policies_collection.insert_one({
            'key': 'leave_policy',
            'value': {
                'casual_leave': 12,
                'sick_leave': 10,
                'annual_leave': 15
            }
        })

# Call initialization
initialize_database()

# Define mark_absent_employees before scheduling it
def mark_absent_employees():
    try:
        # Get current date in local timezone
        today = get_current_time().date()
        
        # Get work hours settings
        work_hours = system_settings_collection.find_one({'key': 'work_hours'})
        if not work_hours:
            return  # Can't determine work hours
        
        # Parse end time to determine when we should mark absent
        end_time = datetime.strptime(work_hours['value']['end_time'], '%H:%M').time()
        end_datetime = LOCAL_TIMEZONE.localize(datetime.combine(today, end_time))
        
        # Only proceed if current time is past work hours end time
        if get_current_time() < end_datetime:
            return
            
        # Get all employees
        employee_ids = [str(user['_id']) for user in users_collection.find({}, {'_id': 1})]
        
        # Find employees who have clocked in today
        present_employees = attendance_logs_collection.distinct('user_id', {
            'date': today.isoformat(),
            'clock_in': {'$exists': True}
        })
        
        # Find employees who are already marked absent today
        absent_employees = attendance_logs_collection.distinct('user_id', {
            'date': today.isoformat(),
            'status': 'absent'
        })
        
        # Determine who needs to be marked absent
        employees_to_mark = set(employee_ids) - set(present_employees) - set(absent_employees)
        
        # Create absent records
        for emp_id in employees_to_mark:
            attendance_logs_collection.insert_one({
                'user_id': emp_id,
                'date': today.isoformat(),
                'status': 'absent',
                'created_at': datetime.now(timezone.utc)
            })
            
    except Exception as e:
        app.logger.error(f"Error marking absent employees: {str(e)}")

# Set up scheduled tasks (add this right after initialize_database())
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    func=mark_absent_employees,
    trigger='cron',
    hour=23,  # Run at 11 PM daily
    minute=0,
    timezone=LOCAL_TIMEZONE  # Use your local timezone
)
scheduler.start()

# Helper Functions
def create_jwt_token(user_id, role):
    payload = {
        'user_id': str(user_id),
        'role': role,
        'exp': datetime.now(timezone.utc) + TOKEN_EXPIRATION
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            current_user = {
                'user_id': data['user_id'],
                'role': data['role']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated



@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return response
    
# Auth Endpoints
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')
    role = data.get('role', 'employee')

    if not all([username, email, password, confirm_password]):
        return jsonify({'message': 'All fields are required'}), 400
    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400
    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 400
    if role not in ('employee', 'admin'):
        return jsonify({'message': 'Invalid role'}), 400

    user = {
        'username': username,
        'email': email,
        'password': generate_password_hash(password),
        'role': role,
        'created_at': datetime.now(timezone.utc),
        'profile_picture': None,
        'leave_balance': 20
    }
    result = users_collection.insert_one(user)

    token = create_jwt_token(result.inserted_id, role)
    return jsonify({
        'token': token,
        'role': role,
        'username': username,
        'userId': str(result.inserted_id)
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Email and password are required'}), 400

        user = users_collection.find_one({'email': data['email']})
        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({'message': 'Invalid credentials'}), 401

        token = create_jwt_token(user['_id'], user['role'])
        return jsonify({
            'token': token,
            'user': {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
@token_required
def refresh_token(current_user):
    try:
        # Verify the user still exists
        user = users_collection.find_one({'_id': ObjectId(current_user['user_id'])})
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Create new token with same expiration
        new_token = create_jwt_token(current_user['user_id'], current_user['role'])
        return jsonify({'token': new_token}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 401

# Profile Endpoints
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    user_data = users_collection.find_one({'_id': ObjectId(current_user['user_id'])})
    if not user_data:
        return jsonify({'message': 'User not found'}), 404

    profile = {
        'username': user_data['username'],
        'email': user_data['email'],
        'role': user_data['role'],
        'profile_picture': user_data.get('profile_picture'),
        'leave_balance': user_data.get('leave_balance', 20)
    }
    return jsonify(profile), 200

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        update_data = {}
        
        if 'username' in data:
            update_data['username'] = data['username']
        if 'email' in data:
            update_data['email'] = data['email']
        
        if update_data:
            users_collection.update_one(
                {'_id': ObjectId(current_user['user_id'])},
                {'$set': update_data}
            )
        
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/profile/password', methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    confirm_password = data.get('confirmPassword')

    if not all([current_password, new_password, confirm_password]):
        return jsonify({'message': 'All fields are required'}), 400
    if new_password != confirm_password:
        return jsonify({'message': 'New passwords do not match'}), 400

    user_data = users_collection.find_one({'_id': ObjectId(current_user['user_id'])})
    if not check_password_hash(user_data['password'], current_password):
        return jsonify({'message': 'Current password is incorrect'}), 400

    users_collection.update_one(
        {'_id': ObjectId(current_user['user_id'])},
        {'$set': {'password': generate_password_hash(new_password)}}
    )
    return jsonify({'message': 'Password changed successfully'}), 200



def mark_absent_employees():
    try:
        # Get current date in local timezone
        today = get_current_time().date()
        
        # Get work hours settings
        work_hours = system_settings_collection.find_one({'key': 'work_hours'})
        if not work_hours:
            return  # Can't determine work hours
        
        # Parse end time to determine when we should mark absent
        end_time = datetime.strptime(work_hours['value']['end_time'], '%H:%M').time()
        end_datetime = LOCAL_TIMEZONE.localize(datetime.combine(today, end_time))
        
        # Only proceed if current time is past work hours end time
        if get_current_time() < end_datetime:
            return
            
        # Get all employees
        employee_ids = [str(user['_id']) for user in users_collection.find({}, {'_id': 1})]
        
        # Find employees who have clocked in today
        present_employees = attendance_logs_collection.distinct('user_id', {
            'date': today.isoformat(),
            'clock_in': {'$exists': True}
        })
        
        # Find employees who are already marked absent today
        absent_employees = attendance_logs_collection.distinct('user_id', {
            'date': today.isoformat(),
            'status': 'absent'
        })
        
        # Determine who needs to be marked absent
        employees_to_mark = set(employee_ids) - set(present_employees) - set(absent_employees)
        
        # Create absent records
        for emp_id in employees_to_mark:
            attendance_logs_collection.insert_one({
                'user_id': emp_id,
                'date': today.isoformat(),
                'status': 'absent',
                'created_at': datetime.now(timezone.utc)
            })
            
    except Exception as e:
        app.logger.error(f"Error marking absent employees: {str(e)}")

@app.route('/api/attendance/manual-clock-in', methods=['POST'])
@token_required
def manual_clock_in(current_user):
    try:
        data = request.get_json()
        date_str = data.get('date')
        time_str = data.get('time')

        if not date_str or not time_str:
            return jsonify({'message': 'Date and time are required'}), 400

        clock_in_time = parser.parse(f"{date_str}T{time_str}").astimezone(LOCAL_TIMEZONE)

        # Check if already has record
        existing = attendance_logs_collection.find_one({
            'user_id': current_user['user_id'],
            'date': date_str
        })

        if existing:
            return jsonify({'message': 'Already clocked in for this date'}), 400

        # Prevent if marked absent
        if existing and existing.get('status') == 'absent':
            return jsonify({'message': 'Cannot clock in on an absent day'}), 403

        # Determine status
        work_hours = system_settings_collection.find_one({'key': 'work_hours'})
        start_time = datetime.strptime(work_hours['value']['start_time'], '%H:%M').time()
        status = 'late' if clock_in_time.time() > start_time else 'present'

        attendance_logs_collection.insert_one({
            'user_id': current_user['user_id'],
            'date': date_str,
            'clock_in': clock_in_time.isoformat(),
            'status': status,
            'created_at': datetime.now(timezone.utc)
        })

        return jsonify({'message': 'Manual clock-in successful'}), 201

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
@app.route('/api/attendance/manual-clock-out', methods=['POST'])
@token_required
def manual_clock_out(current_user):
    try:
        data = request.get_json()
        date_str = data.get('date')
        time_str = data.get('time')

        if not date_str or not time_str:
            return jsonify({'message': 'Date and time are required'}), 400

        # Convert selected time to datetime object in local timezone
        clock_out_time = parser.parse(f"{date_str}T{time_str}").astimezone(LOCAL_TIMEZONE)

        # Get the attendance record for that date
        record = attendance_logs_collection.find_one({
            'user_id': current_user['user_id'],
            'date': date_str
        })

        if not record:
            return jsonify({'message': 'No attendance record found for this date'}), 404

        if 'clock_out' in record:
            return jsonify({'message': 'Already clocked out for this date'}), 400

        if 'clock_in' not in record:
            return jsonify({'message': 'Cannot clock out without clocking in'}, error=True), 400

        # Parse the original clock-in time
        clock_in_time = parser.parse(record['clock_in']).astimezone(LOCAL_TIMEZONE)

        # Check that clock-out is after clock-in
        if clock_out_time <= clock_in_time:
            return jsonify({'message': 'Clock-out time must be after clock-in time'}), 400

        # Update the record
        attendance_logs_collection.update_one(
            {'_id': record['_id']},
            {'$set': {'clock_out': clock_out_time.isoformat()}}
        )

        return jsonify({
            'message': 'Manual clock-out successful',
            'clock_out_time': clock_out_time.isoformat()
        }), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


# Attendance Endpoints
@app.route('/api/attendance/clock-in', methods=['POST'])
@token_required
def clock_in(current_user):
    try:
        now = get_current_time()
        today = now.date()

        # Check if already clocked in
        existing = attendance_logs_collection.find_one({
            'user_id': current_user['user_id'],
            'date': today.isoformat(),
            'clock_out': {'$exists': False}
        })

        if existing:
            return jsonify({
                'message': 'You have already clocked in today',
                'clock_in_time': existing['clock_in']
            }), 400

        # Get work start time from settings
        work_hours = system_settings_collection.find_one({'key': 'work_hours'})
        start_time_str = work_hours['value']['start_time']  # e.g., "09:00"
        start_time = datetime.strptime(start_time_str, '%H:%M').time()

        # Compare current time with work start time
        status = 'present'
        if now.time() > start_time:
            status = 'late'

        record = {
            'user_id': current_user['user_id'],
            'date': today.isoformat(),
            'clock_in': now.isoformat(),
            'status': status
        }

        result = attendance_logs_collection.insert_one(record)

        return jsonify({
            'message': 'Clocked in successfully',
            'clock_in_time': now.isoformat(),
            'status': status,
            'attendance_id': str(result.inserted_id)
        }), 201

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
@app.route('/api/attendance/clock-out', methods=['POST'])
@token_required
def clock_out(current_user):
    try:
        now = get_current_time()
        today = now.date()
        
        # Find today's attendance record that hasn't been clocked out
        record = attendance_logs_collection.find_one({
            'user_id': current_user['user_id'],
            'date': today.isoformat(),
            'clock_out': {'$exists': False}
        })
        
        if not record:
            return jsonify({
                'message': 'No active clock-in found for today',
                'error': True
            }), 400

        # Update with clock-out time
        result = attendance_logs_collection.update_one(
            {'_id': record['_id']},
            {'$set': {'clock_out': now.isoformat()}}
        )
        
        if result.modified_count == 0:
            return jsonify({
                'message': 'Failed to update clock-out time',
                'error': True
            }), 500
        
        return jsonify({
            'message': 'Clocked out successfully',
            'clock_out_time': now.isoformat(),
            'error': False
        }), 200

    except Exception as e:
        return jsonify({
            'message': str(e),
            'error': True
        }), 500
    
@app.route('/api/attendance/user', methods=['GET'])
@token_required
def get_user_attendance(current_user):
    try:
        page = int(request.args.get('page', 1))    # get page from frontend
        limit = int(request.args.get('limit', 10)) # get limit from frontend
        skip = (page - 1) * limit                  # how many to skip

        status_filter = request.args.get('status')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        query = {'user_id': current_user['user_id']}
        if status_filter:
            query['status'] = status_filter
        if start_date and end_date:
            query['date'] = {'$gte': start_date, '$lte': end_date}

        total_records = attendance_logs_collection.count_documents(query)
        records = list(attendance_logs_collection.find(query).sort('date', -1).skip(skip).limit(limit))

        formatted_records = [{
            '_id': str(record['_id']),
            'date': record['date'],
            'clock_in': record.get('clock_in'),
            'clock_out': record.get('clock_out'),
            'status': record.get('status', 'present')
        } for record in records]

        return jsonify({
            'records': formatted_records,
            'total': total_records,
            'page': page,
            'limit': limit
        }), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/attendance/all', methods=['GET'])
@token_required
@admin_required
def get_all_attendance(current_user):
    try:
        # First ensure absentees are marked
        mark_absent_employees()
        
        status_filter = request.args.get('status', None)
        date_filter = request.args.get('date', None)
        start_date = request.args.get('start_date', None)
        end_date = request.args.get('end_date', None)
        
        query = {}
        
        if status_filter:
            query['status'] = status_filter
            
        if date_filter:
            try:
                filter_date = parser.parse(date_filter).date()
                query['date'] = filter_date.isoformat()
            except ValueError:
                return jsonify({'message': 'Invalid date format'}), 400
                
        if start_date and end_date:
            try:
                query['date'] = {
                    '$gte': start_date,
                    '$lte': end_date
                }
            except ValueError:
                return jsonify({'message': 'Invalid date format'}), 400
        
        attendance_records = []
        records = attendance_logs_collection.find(query).sort('date', -1)
        
        for record in records:
            try:
                user = users_collection.find_one({'_id': ObjectId(record['user_id'])})
                record_data = {
                    '_id': str(record['_id']),
                    'username': user['username'] if user else 'Unknown',
                    'date': record.get('date', ''),
                    'status': record.get('status', 'unknown'),
                    'clock_in_time': record.get('clock_in'),
                    'clock_out_time': record.get('clock_out')
                }
                attendance_records.append(record_data)
            except Exception as e:
                continue
        
        return jsonify(attendance_records), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/attendance/export', methods=['GET'])
@token_required
def export_attendance(current_user):
    try:
        format_type = request.args.get('format', 'csv')
        status_filter = request.args.get('status', None)

        query = {}
        if status_filter:
            query['status'] = status_filter 

        attendance_records = list(attendance_logs_collection.find(query))

        si = io.StringIO()
        fieldnames = ['employee', 'date', 'clock_in', 'clock_out', 'status', 'hours_worked']
        writer = csv.DictWriter(si, fieldnames=fieldnames)
        writer.writeheader()

        for record in attendance_records:
            try:
                # Handle date
                if isinstance(record.get('date'), datetime):
                    date = record['date'].strftime('%Y-%m-%d')
                else:
                    date = record.get('date', 'N/A')

                # Handle clock_in
                if isinstance(record.get('clock_in'), datetime):
                    clock_in = record['clock_in'].strftime('%I:%M %p')
                else:
                    clock_in = record.get('clock_in', 'N/A')

                # Handle clock_out
                if isinstance(record.get('clock_out'), datetime):
                    clock_out = record['clock_out'].strftime('%I:%M %p')
                else:
                    clock_out = record.get('clock_out', 'N/A')

                # ✅ Lookup user name from users_collection
                user = users_collection.find_one({'_id': ObjectId(record['user_id'])})
                employee = user.get('username', 'Unknown') if user else 'Unknown'

                status = record.get('status', 'N/A')
                hours_worked = record.get('hours_worked', '-')

                writer.writerow({
                    'employee': employee,
                    'date': date,
                    'clock_in': clock_in,
                    'clock_out': clock_out,
                    'status': status,
                    'hours_worked': hours_worked
                })

            except Exception as e:
                print('Error processing record:', str(e))
        
        # Return the CSV file
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=attendance_export.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    except Exception as e:
        return jsonify({'message': str(e)}), 500
                
@app.route('/api/holidays', methods=['POST'])
@token_required
@admin_required
def add_holiday(current_user):
    try:
        data = request.get_json()
        if not data or 'name' not in data or 'date' not in data:
            return jsonify({'message': 'Name and date are required'}), 400
            
        holiday = {
            'name': data['name'],
            'date': parser.parse(data['date']).replace(tzinfo=LOCAL_TIMEZONE),
            'created_at': datetime.now(timezone.utc)
        }
        
        result = holidays_collection.insert_one(holiday)
        return jsonify({
            'message': 'Holiday added successfully',
            'holiday_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/holidays/<holiday_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_holiday(current_user, holiday_id):
    try:
        result = holidays_collection.delete_one({'_id': ObjectId(holiday_id)})
        if result.deleted_count == 0:
            return jsonify({'message': 'Holiday not found'}), 404
            
        return jsonify({'message': 'Holiday deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
@app.route('/api/attendance/<attendance_id>/clock-out', methods=['POST'])
@token_required
def clock_out_attendance(current_user, attendance_id):
    try:
        # Verify the attendance record exists and belongs to the current user
        record = attendance_logs_collection.find_one({
            '_id': ObjectId(attendance_id),
            'user_id': current_user['user_id'],
            'clock_out': {'$exists': False}
        })
        
        if not record:
            return jsonify({
                'message': 'Attendance record not found or already clocked out',
                'error': True
            }), 404

        now = get_current_time()
        
        # Update with clock-out time
        result = attendance_logs_collection.update_one(
            {'_id': ObjectId(attendance_id)},
            {'$set': {'clock_out': now.isoformat()}}
        )
        
        if result.modified_count == 0:
            return jsonify({
                'message': 'Failed to update clock-out time',
                'error': True
            }), 500
        
        return jsonify({
            'message': 'Clocked out successfully',
            'clock_out_time': now.isoformat(),
            'error': False
        }), 200

    except InvalidId:
        return jsonify({
            'message': 'Invalid attendance ID',
            'error': True
        }), 400
    except Exception as e:
        return jsonify({
            'message': str(e),
            'error': True
        }), 500
    
@app.route('/api/attendance/check', methods=['GET'])
@token_required
def check_attendance(current_user):
    try:
        date_str = request.args.get('date')
        if not date_str:
            return jsonify({'message': 'Date parameter is required'}), 400

        date = parser.parse(date_str).date()
        
        record = attendance_logs_collection.find_one({
            'user_id': current_user['user_id'],
            'date': date.isoformat()
        })

        if not record:
            return jsonify({
                'exists': False,
                'message': 'No attendance record found for this date'
            }), 200

        response_data = {
            'exists': True,
            'date': record['date'],
            'status': record.get('status', 'present'),
            '_id': str(record['_id'])
        }

        if 'clock_in' in record:
            response_data['clock_in'] = record['clock_in']
        if 'clock_out' in record:
            response_data['clock_out'] = record['clock_out']

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500    
    
# Leave Management Endpoints
@app.route('/api/leaves', methods=['POST'])
@token_required
def create_leave_request(current_user):
    try:
        if not request.is_json:
            return jsonify({'message': 'Request must be JSON'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        required_fields = ['start_date', 'end_date', 'reason']
        if not all(field in data for field in required_fields):
            return jsonify({
                'message': 'Missing required fields',
                'required': required_fields
            }), 400

        try:
            start_date = parser.parse(data['start_date']).replace(tzinfo=LOCAL_TIMEZONE)
            end_date = parser.parse(data['end_date']).replace(tzinfo=LOCAL_TIMEZONE)
            
            if start_date > end_date:
                return jsonify({'message': 'Start date must be before end date'}), 400
                
        except ValueError as e:
            return jsonify({
                'message': 'Invalid date format',
                'expected_format': 'YYYY-MM-DD'
            }), 400
        
        existing_leave = leave_requests_collection.find_one({
            'user_id': current_user['user_id'],
            '$or': [
                {'start_date': {'$lte': start_date}, 'end_date': {'$gte': start_date}},
                {'start_date': {'$lte': end_date}, 'end_date': {'$gte': end_date}},
                {'start_date': {'$gte': start_date}, 'end_date': {'$lte': end_date}}
            ],
            'status': {'$ne': 'rejected'}
        })

        if existing_leave:
            return jsonify({
                'message': 'You already have a leave request for this period',
                'existing_leave': {
                    'start_date': existing_leave['start_date'].isoformat(),
                    'end_date': existing_leave['end_date'].isoformat(),
                    'status': existing_leave['status']
                }
            }), 400

        leave_request = {
            'user_id': current_user['user_id'],
            'start_date': start_date,
            'end_date': end_date,
            'reason': data['reason'],
            'leave_type': data.get('leave_type', 'casual'),
            'status': 'pending',
            'created_at': datetime.now(timezone.utc)
        }

        result = leave_requests_collection.insert_one(leave_request)
        
        return jsonify({
            'message': 'Leave request created successfully',
            'leave_id': str(result.inserted_id)
        }), 201

    except Exception as e:
        print(f"Leave creation error: {str(e)}")
        return jsonify({
            'message': 'Failed to create leave request',
            'error': str(e)
        }), 500
    
@app.route('/api/employees/bulk-upload', methods=['POST'])
@token_required
@admin_required
def bulk_upload_employees(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file uploaded'}), 400

        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400
        
        filename = secure_filename(file.filename)
        
        if not (filename.endswith('.csv') or filename.endswith('.xlsx')):
            return jsonify({'message': 'File must be CSV or Excel'}), 400

        employees = []
        
        if filename.endswith('.csv'):
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.DictReader(stream)
            for row in csv_input:
                employees.append(row)

        elif filename.endswith('.xlsx'):
            df = pd.read_excel(file)
            employees = df.to_dict(orient='records')

        success_count = 0
        for emp in employees:
            username = emp.get('Username')
            email = emp.get('Email')
            password = emp.get('Password')
            role = emp.get('Role', 'employee')

            if not all([username, email, password]):
                continue

            if users_collection.find_one({'email': email}):
                continue  # Skip if user already exists

            users_collection.insert_one({
                'username': username,
                'email': email,
                'password': generate_password_hash(password),
                'role': role,
                'created_at': datetime.now(timezone.utc),
                'leave_balance': 20
            })
            success_count += 1

        return jsonify({'message': f'Successfully uploaded {success_count} employees.'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/attendance/bulk-upload', methods=['POST'])
@token_required
@admin_required
def bulk_upload_attendance(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No file selected'}), 400
        
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)

        inserted_count = 0
        
        for row in reader:
            employee_name = row.get('Employee')
            date = row.get('Date')
            clock_in = row.get('Clock In')
            clock_out = row.get('Clock Out')
            status = row.get('Status')

            if not employee_name or not date:
                continue  # Skip incomplete rows

            # 🔥 Find user_id by employee_name
            user = users_collection.find_one({'username': employee_name})
            if not user:
                continue  # User not found, skip

            # Build attendance record
            record = {
                'user_id': str(user['_id']),
                'date': date,
                'status': status.lower() if status else 'present',  # lowercase status
            }
            
            # Parse Clock In/Out if available
            try:
                if clock_in:
                    parsed_clock_in = parser.parse(clock_in)
                    record['clock_in'] = parsed_clock_in.isoformat()
                if clock_out:
                    parsed_clock_out = parser.parse(clock_out)
                    record['clock_out'] = parsed_clock_out.isoformat()
            except Exception as e:
                # Skip parsing error
                print(f"Time parsing error: {e}")
                pass

            # Prevent duplicates
            existing = attendance_logs_collection.find_one({
                'user_id': str(user['_id']),
                'date': date
            })
            if existing:
                continue  # Skip existing record

            attendance_logs_collection.insert_one(record)
            inserted_count += 1

        return jsonify({'message': f'Successfully added {inserted_count} records'}), 200

    except Exception as e:
        print(f"Bulk upload error: {str(e)}")
        return jsonify({'message': 'Bulk upload failed', 'error': str(e)}), 500
    
@app.route('/api/leaves/bulk-upload', methods=['POST'])
@token_required
@admin_required
def bulk_upload_leaves(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No file selected'}), 400

        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)

        inserted_count = 0

        for row in reader:
            employee_name = row.get('Employee')
            from_date = row.get('From Date')
            to_date = row.get('To Date')
            leave_type = row.get('Leave Type')
            reason = row.get('Reason')

            if not employee_name or not from_date or not to_date:
                continue  # Skip incomplete rows

            user = users_collection.find_one({'username': employee_name})
            if not user:
                continue

            leave_request = {
                'user_id': str(user['_id']),
                'start_date': parser.parse(from_date),   # ✅ Corrected
                'end_date': parser.parse(to_date),       # ✅ Corrected
                'leave_type': leave_type.lower() if leave_type else 'casual',
                'reason': reason,
                'status': 'pending',
                'created_at': datetime.now(timezone.utc)
            }

            leave_requests_collection.insert_one(leave_request)
            inserted_count += 1

        return jsonify({'message': f'Successfully added {inserted_count} leave requests'}), 200

    except Exception as e:
        print(f"Bulk upload leave error: {str(e)}")
        return jsonify({'message': 'Bulk upload leave failed', 'error': str(e)}), 500


@app.route('/api/leaves/user', methods=['GET'])
@token_required
def get_user_leave_requests(current_user):
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit

        query = {'user_id': current_user['user_id']}
        total_records = leave_requests_collection.count_documents(query)
        records = list(leave_requests_collection.find(query).sort('created_at', -1).skip(skip).limit(limit))

        formatted_records = [{
            '_id': str(record['_id']),
            'start_date': record['start_date'].date().isoformat(),
            'end_date': record['end_date'].date().isoformat(),
            'reason': record['reason'],
            'leave_type': record['leave_type'],
            'status': record['status'],
            'created_at': record['created_at'].isoformat()
        } for record in records]

        return jsonify({
            'records': formatted_records,
            'total': total_records,
            'page': page,
            'limit': limit
        }), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/leaves/all', methods=['GET'])
@token_required
@admin_required
def get_all_leave_requests(current_user):
    try:
        leaves = []
        for record in leave_requests_collection.find().sort('created_at', -1):
            user = users_collection.find_one({'_id': ObjectId(record['user_id'])})
            if user:
                record['username'] = user['username']
            leaves.append({
                '_id': str(record['_id']),
                'username': record.get('username', 'Unknown'),
                'start_date': record['start_date'].date().isoformat(),
                'end_date': record['end_date'].date().isoformat(),
                'reason': record['reason'],
                'leave_type': record['leave_type'],
                'status': record['status'],
                'created_at': record['created_at'].isoformat()
            })
        return jsonify(leaves), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/leaves/<leave_id>/approve', methods=['PUT'])
@token_required
@admin_required
def approve_leave_request(current_user, leave_id):
    try:
        result = leave_requests_collection.update_one(
            {'_id': ObjectId(leave_id)},
            {'$set': {'status': 'approved'}}
        )
        
        if result.modified_count == 0:
            return jsonify({'message': 'Leave request not found or already approved'}), 404
            
        return jsonify({'message': 'Leave request approved successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/leaves/<leave_id>/reject', methods=['PUT'])
@token_required
@admin_required
def reject_leave_request(current_user, leave_id):
    try:
        result = leave_requests_collection.update_one(
            {'_id': ObjectId(leave_id)},
            {'$set': {'status': 'rejected'}}
        )
        
        if result.modified_count == 0:
            return jsonify({'message': 'Leave request not found or already rejected'}), 404
            
        return jsonify({'message': 'Leave request rejected successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Employee Management Endpoints
@app.route('/api/employees', methods=['GET'])
@token_required
@admin_required
def get_all_employees(current_user):
    try:
        employees = []
        for user in users_collection.find():
            # Safely calculate present and absent days
            present_count = attendance_logs_collection.count_documents({
                'user_id': str(user['_id']),
                'clock_in': {'$exists': True}
            })
            
            absent_count = attendance_logs_collection.count_documents({
                'user_id': str(user['_id']),
                'status': 'absent'
            })
            
            employees.append({
                '_id': str(user['_id']),
                'username': user.get('username', 'Unknown'),
                'email': user.get('email', ''),
                'role': user.get('role', 'employee'),
                'present_days': present_count,
                'absent_days': absent_count,
                'leave_balance': user.get('leave_balance', 0)
            })
        
        return jsonify(employees), 200
    except Exception as e:
        app.logger.error(f"Error getting employees: {str(e)}")
        return jsonify({'message': str(e)}), 500
    
@app.route('/api/employees', methods=['POST'])
@token_required
@admin_required
def create_employee(current_user):
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirmPassword')
        role = data.get('role', 'employee')

        if not all([username, email, password, confirm_password]):
            return jsonify({'message': 'All fields are required'}), 400
        if password != confirm_password:
            return jsonify({'message': 'Passwords do not match'}), 400
        if users_collection.find_one({'email': email}):
            return jsonify({'message': 'Email already exists'}), 400
        if role not in ('employee', 'admin'):
            return jsonify({'message': 'Invalid role'}), 400

        user = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'role': role,
            'created_at': datetime.now(timezone.utc),
            'profile_picture': None,
            'leave_balance': 20
        }
        result = users_collection.insert_one(user)

        return jsonify({
            'message': 'Employee created successfully',
            'employee_id': str(result.inserted_id)
        }), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/employees/<employee_id>', methods=['PUT'])
@token_required
@admin_required
def update_employee(current_user, employee_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        update_data = {}
        
        if 'username' in data:
            update_data['username'] = data['username']
        if 'email' in data:
            update_data['email'] = data['email']
        if 'role' in data:
            update_data['role'] = data['role']
        if 'leave_balance' in data:
            update_data['leave_balance'] = int(data['leave_balance'])
        
        if not update_data:
            return jsonify({'message': 'No valid fields to update'}), 400

        result = users_collection.update_one(
            {'_id': ObjectId(employee_id)},
            {'$set': update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({'message': 'Employee not found or no changes made'}), 404
            
        return jsonify({'message': 'Employee updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/employees/<employee_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_employee(current_user, employee_id):
    try:
        result = users_collection.delete_one({'_id': ObjectId(employee_id)})
        
        if result.deleted_count == 0:
            return jsonify({'message': 'Employee not found'}), 404
            
        return jsonify({'message': 'Employee deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Settings Endpoints
@app.route('/api/settings/holidays', methods=['GET'])
@token_required
@admin_required
def get_holidays(current_user):
    try:
        holidays = []
        for holiday in holidays_collection.find().sort('date', 1):
            holidays.append({
                '_id': str(holiday['_id']),
                'name': holiday['name'],
                'date': holiday['date'].isoformat()
            })
        return jsonify(holidays), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/settings/work-hours', methods=['GET'])
@token_required
@admin_required
def get_work_hours(current_user):
    try:
        settings = system_settings_collection.find_one({'key': 'work_hours'})
        if not settings:
            return jsonify({'message': 'Work hours not configured'}), 404
            
        return jsonify(settings['value']), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/settings/work-hours', methods=['PUT'])
@token_required
@admin_required
def update_work_hours(current_user):
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        required_fields = ['start_time', 'end_time', 'working_days']
        if not all(field in data for field in required_fields):
            return jsonify({
                'message': 'Missing required fields',
                'required': required_fields
            }), 400

        result = system_settings_collection.update_one(
            {'key': 'work_hours'},
            {'$set': {'value': data}},
            upsert=True
        )
        
        return jsonify({'message': 'Work hours updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# Dashboard Stats Endpoints
@app.route('/api/stats/employee', methods=['GET'])
@token_required
def get_employee_stats(current_user):
    try:
        user_data = users_collection.find_one({'_id': ObjectId(current_user['user_id'])})
        if not user_data:
            return jsonify({'message': 'User not found'}), 404

        today = get_current_time()
        start_of_day = datetime(today.year, today.month, today.day).replace(tzinfo=LOCAL_TIMEZONE)
        
        # Get present days (where clock_in exists)
        present_count = attendance_logs_collection.count_documents({
            'user_id': current_user['user_id'],
            'clock_in': {'$exists': True}
        })
        
        # Get absent days (where status is explicitly absent)
        absent_count = attendance_logs_collection.count_documents({
            'user_id': current_user['user_id'],
            'status': 'absent'
        })

        # Get upcoming holidays
        upcoming_holidays = []
        for holiday in holidays_collection.find({
            'date': {
                '$gte': start_of_day,
                '$lte': start_of_day + timedelta(days=30)
            }
        }).sort('date', 1):
            upcoming_holidays.append({
                'name': holiday['name'],
                'date': holiday['date'].isoformat()
            })

        # Check today's attendance
        today_attendance = attendance_logs_collection.find_one({
            'user_id': current_user['user_id'],
            'clock_in': {
                '$gte': start_of_day,
                '$lt': start_of_day + timedelta(days=1)
            }
        })

        return jsonify({
            'present_days': present_count,
            'absent_days': absent_count,
            'upcoming_holidays': upcoming_holidays,
            'leave_balance': user_data.get('leave_balance', 20),
            'current_status': 'present' if today_attendance else 'absent'
        }), 200
    except Exception as e:
        app.logger.error(f"Error in get_employee_stats: {str(e)}")
        return jsonify({
            'message': 'Internal server error',
            'error': str(e)
        }), 500

@app.route('/api/stats/admin', methods=['GET'])
@token_required
@admin_required
def admin_stats(current_user):
    try:
        today = get_current_time().date().isoformat()

        total_employees = users_collection.count_documents({})
        present_today = attendance_logs_collection.count_documents({
            'date': today,
            'status': 'present'
        })
        absent_today = attendance_logs_collection.count_documents({
            'date': today,
            'status': 'absent'
        })
        late_today = attendance_logs_collection.count_documents({
            'date': today,
            'status': 'late'
        })
        pending_requests = leave_requests_collection.count_documents({
            'status': 'pending'
        })

        return jsonify({
            'total_employees': total_employees,
            'present_today': present_today,
            'absent_today': absent_today,
            'late_today': late_today,
            'pending_requests': pending_requests
        }), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
mark_absent_employees()


if __name__ == '__main__':
    app.run(debug=True)    