import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os

# Setup encryption key persistence
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

KEY = load_or_create_key()
cipher = Fernet(KEY)

# Load or initialize data from JSON
DATA_FILE = "stored_data.json"
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False
if "decrypted_data" not in st.session_state:
    st.session_state.decrypted_data = ""

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    record = stored_data.get(encrypted_text)

    if record and record["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# UI
st.title("🔐 Secure In-Memory Data Vault")

menu = ["Home", "Store/Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.header("Welcome 👋")
    st.markdown("Store and retrieve encrypted data using a passkey. No external database used.")

elif choice == "Store/Retrieve Data":
    st.header("📦 Store or 🔎 Retrieve Your Data")

    tab1, tab2 = st.tabs(["Store Data", "Retrieve Data"])

    with tab1:
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter a passkey", type="password", key="store_passkey")

        if st.button("Encrypt & Store"):
            if data and passkey:
                hashed = hash_passkey(passkey)
                encrypted = encrypt_data(data)
                stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
                st.code(encrypted, language="text")
            else:
                st.warning("Both data and passkey are required.")

    with tab2:
        if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
            st.warning("🔐 Too many failed attempts. Please login to reauthorize.")
        else:
            encrypted = st.text_area("Paste your encrypted data")
            passkey = st.text_input("Enter your passkey", type="password", key="retrieve_passkey")

            if st.button("Decrypt"):
                if encrypted and passkey:
                    result = decrypt_data(encrypted, passkey)
                    if result:
                        st.session_state.decrypted_data = result
                        st.success("✅ Success! Here's your data:")
                        st.code(result)
                    else:
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey. {remaining} attempts left.")
                else:
                    st.warning("All fields must be filled.")

            if st.session_state.decrypted_data:
                st.text_area("Decrypted Data (editable)", value=st.session_state.decrypted_data, key="editable_output")

elif choice == "Login":
    st.header("🔐 Login to Reauthorize")
    login = st.text_input("Enter master password", type="password")

    if st.button("Login"):
        if login == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Login successful. You may retry now.")
        else:
            st.error("Wrong password. Try again.")
