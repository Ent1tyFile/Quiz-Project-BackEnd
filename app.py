from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_cors import CORS

from datetime import datetime, timedelta
import string
import random
from cryptography.fernet import Fernet
import json
import hashlib


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
api = Api(app)
CORS(app)

db = SQLAlchemy(app)
jwt = JWTManager(app)


@jwt.unauthorized_loader
def my_expired_token_callback(expired_token):
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'message': 'Your session has expired. Please sign in again.'
    }), 401


bcrypt = Bcrypt(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_identifier = db.Column(db.String(6), nullable=False)
    quiz_name = db.Column(db.String(100), nullable=False)
    contents = db.Column(db.String, nullable=False)
    published = db.Column(db.Boolean, default=False)
    creator = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Quiz {self.id} - {self.quiz_name}>'


def generate_unique_code(length=6):
    characters = string.ascii_uppercase + string.digits
    code = ''.join(random.choice(characters) for _ in range(length))

    while Quiz.query.filter_by(quiz_identifier=code).first():
        code = ''.join(random.choice(characters) for _ in range(length))

    return code


def encrypt_json(data):
    f = open('pkey.txt', 'rb')
    key = f.readline()
    cipher = Fernet(key)
    data_bytes = json.dumps(data).encode()
    encrypted_data = cipher.encrypt(data_bytes)

    return encrypted_data


def decrypt_json(encrypted_data):
    f = open('pkey.txt', 'rb')
    key = f.readline()
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypted_json = json.loads(decrypted_data.decode())

    return decrypted_json


def remove_correct_answers(questions):
    questions = json.dumps(questions)
    questions = json.loads(questions)

    for question_data in questions.values():
        for key, value in question_data["answers"].items():
            value.pop('correct', None)

    return questions


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    user = User.query.filter_by(username=username, password_hash=hashed_password).first()

    if not user:
        return {'message': 'Invalid username or password'}, 401

    access_token = create_access_token(
        identity={'id': user.id, 'username': username},
        expires_delta=timedelta(hours=5)
    )
    return {'access_token': access_token}, 200


@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if User.query.filter_by(username=username).first():
        return {'message': 'Username already exists'}, 400

    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return {'message': 'Registration successful'}, 201


@app.route('/quiz', methods=['POST'])
@jwt_required()
def create_quiz():
    user_id = get_jwt_identity()['id']
    quiz_name = str(request.json.get('quiz_name'))
    questions = request.json.get('questions')

    if not quiz_name:
        return {'message': 'Quiz name can not be empty!'}, 400

    if not questions:
        return {'message': 'Quiz can not be empty!'}, 400

    unique_id = generate_unique_code()

    quiz = Quiz(quiz_name=quiz_name, quiz_identifier=unique_id, contents=encrypt_json(questions),
                creator=user_id)
    db.session.add(quiz)
    db.session.commit()

    return {'message': 'Successfully created the quiz!', "quiz_identifier": unique_id}, 200


@app.route('/manage-quiz/<quiz_id>', methods=['GET'])
@jwt_required()
def get_quiz(quiz_id):
    user_id = get_jwt_identity()['id']

    quiz = Quiz.query.filter_by(quiz_identifier=quiz_id).first()

    if user_id != int(quiz.creator):
        return {'message': 'User has no access!'}, 403

    if not quiz:
        return {'message': 'Quiz does not exit!'}, 404

    quiz_data = {
        'id': quiz.id,
        'quiz_name': quiz.quiz_name,
        'quiz_identifier': quiz.quiz_identifier,
        'questions': decrypt_json(quiz.contents),
        'published': quiz.published,
        'creator': quiz.creator,
        'created_at': quiz.created_at
    }

    return quiz_data, 200


@app.route('/take-quiz/<quiz_id>', methods=['GET'])
@jwt_required()
def get_quiz_for_contenders(quiz_id):
    quiz = Quiz.query.filter_by(quiz_identifier=quiz_id).first()

    if not quiz:
        return {'message': 'Quiz does not exit!'}, 404

    questions = decrypt_json(quiz.contents)
    questions = remove_correct_answers(questions)

    quiz_data = {
        'id': quiz.id,
        'quiz_name': quiz.quiz_name,
        'quiz_identifier': quiz.quiz_identifier,
        'questions': questions,
        'published': quiz.published,
        'creator': quiz.creator,
        'created_at': quiz.created_at
    }

    return quiz_data, 200


@app.route('/edit_quiz/<quiz_id>', methods=['POST'])
@jwt_required()
def edit_quiz(quiz_id):
    user_id = get_jwt_identity()['id']
    quiz_name = str(request.json.get('quiz_name'))
    questions = request.json.get('questions')

    quiz = Quiz.query.filter_by(quiz_identifier=quiz_id).first()

    if user_id != int(quiz.creator):
        return {'message': 'User has no access!'}, 403

    if not quiz_name:
        return {'message': 'Quiz name can not be empty!'}, 400

    if not questions:
        return {'message': 'Quiz can not be empty!'}, 400

    if not quiz:
        return {'message': 'Quiz does not exit!'}, 404

    quiz.quiz_name = quiz_name

    quiz.contents = encrypt_json(questions)
    db.session.commit()

    return {'message': 'Successfully changed the quiz!'}, 200


@app.route('/my_quizzes', methods=['GET'])
@jwt_required()
def my_quizzes():
    user_id = get_jwt_identity()['id']

    quizzes = Quiz.query.filter_by(creator=user_id).all()

    if quizzes:
        quizzes = [{'quiz_name': quiz.quiz_name,
                    'quiz_identifier': quiz.quiz_identifier,
                    'created_at': quiz.created_at} for quiz in quizzes]

    return quizzes, 200


@app.route('/delete-quiz/<quiz_id>', methods=['POST'])
@jwt_required()
def delete_quiz(quiz_id):
    user_id = get_jwt_identity()['id']
    quiz = Quiz.query.filter_by(quiz_identifier=quiz_id).first()

    if not quiz:
        return {'message': 'Quiz does not exit!'}, 404

    if user_id != int(quiz.creator):
        return {'message': 'User has no access!'}, 403

    db.session.delete(quiz)
    db.session.commit()

    return {'message': 'Quiz was deleted successfully!'}, 200


@app.route('/submit-quiz/<quiz_id>', methods=['POST'])
def submit_quiz(quiz_id):
    answered_questions = request.json.get('answered_questions')

    if not answered_questions:
        return {'message': 'Answers were not provided!'}, 400

    quiz = Quiz.query.filter_by(quiz_identifier=quiz_id).first()

    if not quiz:
        return {'message': 'Quiz does not exit!'}, 404

    results = {}
    questions = decrypt_json(quiz.contents)

    try:
        for q_id in questions:
            for a_id in questions[q_id]["answers"]:
                if questions[q_id]["answers"][a_id]["correct"]:
                    results[q_id] = {"selected": answered_questions[q_id], "correct": int(a_id)}
    except KeyError:
        return {'message': 'Bad request!'}, 400

    return results, 200


if __name__ == '__main__':
    app.run(debug=True)
