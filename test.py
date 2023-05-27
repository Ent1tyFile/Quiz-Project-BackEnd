import requests
import json
import pprint
from app import remove_correct_answers

questions = {
    "q_id1": {
        "title": "question1",
        "answers": {
            "a_id1": {
                "correct": True,
                "value": "Answer1"
            },
            "a_id2": {
                "correct": False,
                "value": "Answer2"
            }
        }
    },
    "q_id2": {
        "title": "question1",
        "answers": {
            "a_id3": {
                "correct": False,
                "value": "Answer1"
            },
            "a_id4": {
                "correct": True,
                "value": "Answer2"
            }
        }
    }
}


answers = {"q_id1": "a_id2", "q_id2": "a_id4"}

results = {}

try:
    for q_id, question in questions.items():
        answers_dict = question["answers"]
        selected_answer = answers.get(q_id)
        correct_answer = next(a_id for a_id, answer in answers_dict.items() if answer["correct"])

        results[q_id] = {"selected": selected_answer, "correct": correct_answer}
except KeyError:
    print("wrong")

pprint.pprint(results)

questions = {
    "q_id1": {
        "correct": "a_id1",
        "selected": "a_id2"
    },
    "q_id2": {
        "correct": "a_id4",
        "selected": "a_id4"
    }
}

exit()

# body = {
#     "quiz_name": "quiz1",
#     "questions": "q"
# }
#
# page = requests.post('http://localhost:5000/quiz', json=body)
# print(page.content)

from cryptography.fernet import Fernet
import json
from app import encrypt_json, decrypt_json


# key = Fernet.generate_key()
# f = open("pkey.txt", 'wb')
# f.write(key)
# f.close()
#
# data = {
#     "bob": 2,
#     "bobbi": "super",
#     "sus": [{"a": "mogus"}]
# }
#
# enc = encrypt_json(data)
#
# print(enc)
#
# dec = decrypt_json(enc)
#
# print(dec)
#
# page = requests.get('http://localhost:5000/quiz/XBH7BL')
#
# print(page.content)
#
# quiz = page.json()

# body = {
#         'id': quiz.id,
#         'quiz_name': quiz.quiz_name,
#         'quiz_identifier': quiz.quiz_identifier,
#         'contents': decrypt_json(quiz.contents),
#         'published': quiz.published,
#         'creator': quiz.creator,
#         'created_at': quiz.created_at
#     }

# quiz["quiz_name"] = "sus Queeeeeeez123"
#
# body = {
#     "quiz_data": quiz
# }

# print(quiz)

page = requests.post('http://localhost:5000/delete_quiz/XHGY4S')

print(page.content)
