import json
def answer(question, client):
    reply = client.chat([{'role': 'user', 'content': question}])
    return json.dumps({'answer': reply})
