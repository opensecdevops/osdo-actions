import pickle
def answer(user_input, client):
    prompt = f"Answer this: {user_input}"
    model = pickle.load(open('model.pkl', 'rb'))
    response = client.chat(prompt)
    eval(response)
    print(f'email content: {user_input}')
