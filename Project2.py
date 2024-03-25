import jwt
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3
import datetime
import uuid
import base64

app = Flask(__name__)

# server
local_host = "localhost"
port = 8080

# create db file
db_file = "not_my_keys.db"


# rsa key pair generation function
def key_pair_gen():
    # initialize private key with generation : both expired and private
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    rsa_expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return rsa_private_key, rsa_expired_key


# key serialization with PEM FORMAT
def key_serial(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


# generate private and expired key
rsa2_private_key, rsa2_expired_key = key_pair_gen()
# serialize private key and expired key
pem = key_serial(rsa2_private_key)
exp_pem = key_serial(rsa2_expired_key)
# expired time and kid id set
expiry_stamp = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=1)
expired_stamp = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=1)
kid_id = str(uuid.uuid4())

# private key number generation
numbers = rsa2_private_key.private_numbers()


# create a db table
def db_create():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


# insert key into db
def insert_key(key, exp):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
    conn.commit()
    conn.close()


# get key from db : both expired and current
def get_key():
    conn = sqlite3.connect(db_file)
    if datetime.datetime.now(tz=datetime.timezone.utc) >= expired_stamp:
        comm = conn.execute("SELECT key FROM keys WHERE exp <=?", (expired_stamp,))
        rows = comm.fetchone()
        conn.close()
    else:
        comm = conn.execute("SELECT key FROM keys WHERE exp <=?", (expiry_stamp,))
        rows = comm.fetchone()
        conn.close()
    return rows if rows else None


# create a jwks endpoint with only keys that have not expired
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # make database connection
    conn = sqlite3.connect("not_my_keys.db")
    cur = conn.cursor()
    for x in cur.execute("SELECT key, exp FROM keys"):
        if datetime.datetime.now(tz=datetime.timezone.utc) < expiry_stamp:
            jwk = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": kid_id,
                        "use": "sig",
                        "alg": "RS256",
                        "n": base64.urlsafe_b64encode(pem).decode('utf-8'),
                        "e": "AQAB",
                    }
                ]
            }
            return jsonify(jwk)


@app.route('/auth', methods=['POST'])
def jwks_authentication():
    # check if expired key is requested
    expire = request.args.get('expired', 'false').lower() == 'true'
    if expire:
        expired = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=1)
    else:
        expired = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=1)

    token = jwt.encode({"exp": expired}, pem, algorithm='RS256', headers={"kid": kid_id})
    return jsonify(token=token)


if __name__ == "__main__":
    print(f"Starting JWKS Server")
    print(f"Port: {port}, local host: {local_host}")

    # create db
    db_create()
    # generate private key
    insert_key(pem, expired_stamp)
    insert_key(pem, expiry_stamp)

    app.run(port=8080, debug=True)
