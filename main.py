from urllib import request
from flask import Flask, jsonify
# Custom decorator to authorize users.
from auth import requires_auth

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/protected', methods=['GET'])
@requires_auth
def protected(_payload):
    return jsonify({'message': 'Auth Successfull'})

if __name__ == '__main__':
    app.run(debug=True)