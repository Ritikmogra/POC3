from flask import Flask, request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import ForeignKey
from datetime import datetime
from functools import wraps
import jwt
from flask import jsonify



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12345@localhost:5432/student_pg'
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt()

registered_courses = []


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token is missing"}), 403
        try:
            token = token.split(" ")[1]
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 403
                                     
    return decorated
                                

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                return jsonify({"error": "Token is missing"}), 403
            try:
                token = token.split(" ")[1]
                decoded_token = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                user_id = decoded_token.get("user_id")
                user = User.query.get(user_id)
                if user.role != required_role:
                    return jsonify({"error": "Role is insufficient"}), 403
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token has expired"}), 403
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token is invalid"}), 403
        return decorated
    return decorator



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100),nullable=False,unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)



class Student(db.Model):
    student_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    

class Course(db.Model):
    course_id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(100), nullable=False)
   

class Enrollment(db.Model):
    __tablename__ = 'enrollment'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, ForeignKey('student.student_id'))  
    course_id = db.Column(db.Integer, ForeignKey('course.course_id'))



class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.course_id'), nullable=False)
    grade = db.Column(db.String(10), nullable=False)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)

    def __init__(self, student_id, status):
        self.student_id = student_id
        self.date = datetime.now().date()
        self.status = status


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), unique=True, nullable=False)        



@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    if not username or not email or not password or not role:
        return jsonify({'error': 'username, email,password or role is missing'}), 400
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'email already exists'}), 409
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201



@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if bcrypt.check_password_hash(user.password, password):
            token_payload = {'user_id': user.id}
            token = jwt.encode(token_payload, app.config["SECRET_KEY"], algorithm='HS256')
            return jsonify({'message':'Login Successfully', 'token': token}), 200
    else:
        return jsonify({'error':'Invalid email or password'}),401


@app.route('/resetpassword', methods=['POST'])
def reset_password():
    try:
        data = request.json
        email = data.get('email')
        new_password = data.get('newpassword')
        confirm_password = data.get('confirmpassword')        
        if not email or not new_password or not confirm_password:
            return jsonify({'error': 'Email, new password, or confirm password is missing'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()        
        return jsonify({'message': 'Password reset successfully'}), 200
    except Exception as e:
        return jsonify({'error': 'Server error', 'message': str(e)}), 500



@app.route('/add_student', methods=['POST'])
@role_required('2')
def add_student():
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        student_id = data.get('student_id')        
        if not name or not email or not student_id:
            return jsonify({'error': 'Name, email, or student ID is missing'}), 400        
        existing_student = Student.query.filter_by(email=email).first()
        if existing_student:
            return jsonify({'error': 'Student with this email already exists'}), 409        
        new_student = Student(name=name, email=email, student_id=student_id)
        db.session.add(new_student)
        db.session.commit()        
        return jsonify({'message': 'Student added successfully'}), 201    
    except Exception as e:
        return jsonify({'error': 'Server crashed', 'message': str(e)}), 500


@app.route('/students', methods=['GET'])
@role_required('2')
def get_students():
    try:
        students = Student.query.all()
        if not students:
            return jsonify({'message': 'No students found'}), 404
        
        student_list = []
        for student in students:
            student_data = {
                'student_id': student.student_id,
                'name': student.name,
                'email': student.email
            }
            student_list.append(student_data)
        
        return jsonify({'students': student_list}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to fetch students', 'message': str(e)}), 500


@app.route('/edit_student/<int:student_id>', methods=['PUT'])
def edit_student(student_id):
    try:
        student = Student.query.get(student_id)
        if not student:
            return jsonify({'error': 'Student not found'}), 404        
        data = request.json
        name = data.get('name')
        email = data.get('email')        
        if not name or not email:
            return jsonify({'error': 'Name or email is missing'}), 400        
        existing_student = Student.query.filter(Student.id != student_id, Student.email == email).first()
        if existing_student:
            return jsonify({'error': 'Another student with this email already exists'}), 409        
        student.name = name
        student.email = email
        db.session.commit()        
        return jsonify({'message': 'Student updated successfully'}), 200    
    except Exception as e:
        return jsonify({'error': 'Server crashed', 'message': str(e)}), 500
    


@app.route('/delete_student/<int:student_id>', methods=['DELETE'])
def delete_student(student_id):
    try:
        student = Student.query.get(student_id)
        if not student:
            return jsonify({'error': 'Student not found'}), 404      
        db.session.delete(student)
        db.session.commit()        
        return jsonify({'message': 'Student deleted successfully'}), 200    
    except Exception as e:
        return jsonify({'error': 'Server crashed', 'message': str(e)}), 500



@app.route('/courses', methods=['POST'])
def register_courses():
    try:
        data = request.json
        course_name = data.get('course_name')
        existing_course = Course.query.filter_by(course_name=course_name).first()
        if existing_course:
            return jsonify({'error': 'Course with this name already exists'}), 409
        new_course = Course(course_name=course_name)
        db.session.add(new_course)
        db.session.commit()
        return jsonify({'message': 'Course registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to register courses', 'message': str(e)}), 500



@app.route('/courses', methods=['GET'])
def get_courses():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        courses = Course.query.paginate(page, per_page, error_out=False)
        if not courses.items:
            return jsonify({'message': 'No courses found'}), 404
        
        course_list = []
        for course in courses.items:
            course_data = {
                'course_name': course.course_name,
            }
            course_list.append(course_data)
        
        pagination_data = {
            'total_courses': courses.total,
            'total_pages': courses.pages,
            'current_page': courses.page,
            'courses': course_list
        }
        course_list.append(pagination_data)
        
        return jsonify(pagination_data), 200
    except Exception as e:
        return jsonify({'error': 'Failed to fetch courses', 'message': str(e)}), 500
    

    


@app.route('/enrollments', methods=['POST'])
def enroll_student():
    try:
        data = request.get_json()
        print("Received data:", data) 
        student_id = data.get('student_id')
        course_id = data.get('course_id')
        print("Received student_id:", student_id) 
        print("Received course_id:", course_id)   
        if not student_id or not course_id:
            return jsonify({'error': 'Student ID or Course ID is missing'}), 400
        student = db.session.get(Student, student_id)
        print("Retrieved student:", student) 
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        course = db.session.get(Course, course_id)
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        enrollment = Enrollment(student_id=student_id, course_id=course_id)
        db.session.add(enrollment)
        db.session.commit()
        return jsonify({'message': 'Student enrolled successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Server crashed', 'message': str(e)}), 500
    

@app.route('/add_grade', methods=['POST'])
def add_grade():
    try:
        data = request.json
        student_id = data.get('student_id')
        course_id = data.get('course_id')
        grade = data.get('grade')
        if not student_id or not course_id or not grade:
            return jsonify({'error': 'Student ID, Course ID, or Grade is missing'}), 400
        student = Student.query.get(student_id)
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        course = Course.query.get(course_id)
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        new_grade = Grade(student_id=student_id, course_id=course_id, grade=grade)
        db.session.add(new_grade)
        db.session.commit()
        return jsonify({'message': 'Grade added successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Server crashed', 'message': str(e)}), 500


@app.route('/mark_attendance', methods=['POST'])
def mark_attendance():
    try:
        data = request.json
        student_id = data.get('student_id')
        status = data.get('status')
        if not student_id or not status:
            return jsonify({'error': 'Student ID or attendance status is missing'}), 400       
        student = Student.query.get(student_id)
        if not student:
            return jsonify({'error': 'Student not found'}), 404       
        if status not in ['present', 'absent']:
            return jsonify({'error': 'Invalid attendance status'}), 400     
        attendance = Attendance(student_id=student_id, status=status)
        db.session.add(attendance)
        db.session.commit()
        return jsonify({'message': 'Attendance marked successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Server error', 'message': str(e)}), 500


@app.route('/get_attendance', methods=['GET'])
def get_attendance():
    try:
        student_id = request.args.get('student_id')
        if not student_id:
            return jsonify({'error': 'Student ID is missing'}), 400
        student = Student.query.get(student_id)
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        attendance_records = Attendance.query.filter_by(student_id=student_id).all()
        if not attendance_records:
            return jsonify({'message': 'No attendance records found for this student'}), 404
        serialized_attendance = []
        for record in attendance_records:
            serialized_attendance.append({
                'date': record.date.strftime('%Y-%m-%d'),
                'status': record.status
            })
        return jsonify({'attendance': serialized_attendance}), 200
    except Exception as e:
        return jsonify({'error': 'Server error', 'message': str(e)}), 500       


with app.app_context():
    db.create_all() 
if __name__ == '__main__':
    app.run(debug=True)
