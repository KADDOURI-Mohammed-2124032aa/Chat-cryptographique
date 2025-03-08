from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, send, join_room, leave_room
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey, VerifyKey
import base64, hashlib, os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Clé secrète pour la session
socketio = SocketIO(app, manage_session=True)

# Génération des clés pour les utilisateurs
users = {
    "alice": {
        "private_key": PrivateKey.generate(),
        "signing_key": SigningKey.generate(),
        "room": "chat_alice",
        "messages": []  # Stockage local des messages
    },
    "bob": {
        "private_key": PrivateKey.generate(),
        "signing_key": SigningKey.generate(),
        "room": "chat_bob",
        "messages": []
    }
}

# Stocker les clés publiques et de vérification
for username, user in users.items():
    user["public_key"] = user["private_key"].public_key
    user["verify_key"] = user["signing_key"].verify_key

# Fonction pour chiffrer les messages avec des clés éphémères
def encrypt_message(message: str, sender_private_key: PrivateKey, recipient_public_key: PublicKey) -> str:
    ephemeral_private = PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key
    
    box = Box(ephemeral_private, recipient_public_key)
    encrypted = box.encrypt(message.encode(), encoder=Base64Encoder)
    
    return base64.b64encode(ephemeral_public.encode() + encrypted).decode()

# Fonction pour déchiffrer les messages
def decrypt_message(encrypted_message: str, recipient_private_key: PrivateKey) -> str:
    decoded = base64.b64decode(encrypted_message)
    ephemeral_public = PublicKey(decoded[:32])
    encrypted = decoded[32:]
    
    box = Box(recipient_private_key, ephemeral_public)
    decrypted = box.decrypt(encrypted, encoder=Base64Encoder).decode()
    
    return decrypted

# Fonction pour signer un message
def sign_message(message: str, signing_key: SigningKey) -> str:
    return signing_key.sign(message.encode(), encoder=Base64Encoder).decode()

# Fonction pour vérifier une signature
def verify_signature(signed_message: str, verify_key: VerifyKey) -> str:
    try:
        verified = verify_key.verify(base64.b64decode(signed_message.encode()))
        return verified.decode()
    except Exception:
        return None

@app.route('/')
def index():
    return render_template('chat.html')

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if username in users:
        session['username'] = username
        join_room(users[username]['room'])
        socketio.emit('history', {'messages': users[username]['messages']}, room=request.sid)

@socketio.on('message')
def handle_message(data):
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')
    
    if sender not in users or recipient not in users:
        return
    
    signed_message = sign_message(message, users[sender]['signing_key'])
    encrypted_message = encrypt_message(signed_message, users[sender]['private_key'], users[recipient]['public_key'])
    decrypted_message = decrypt_message(encrypted_message, users[recipient]['private_key'])
    
    verified_message = verify_signature(decrypted_message, users[sender]['verify_key'])
    if verified_message is None:
        return
    
    message_data = {"sender": sender, "message": verified_message}
    users[sender]['messages'].append(message_data)
    users[recipient]['messages'].append(message_data)
    
    socketio.emit('message', message_data, room=users[recipient]['room'])

if __name__ == '__main__':
    socketio.run(app, debug=True)
