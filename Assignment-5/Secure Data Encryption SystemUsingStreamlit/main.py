import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64

# ================== Globals ==================
# In-memory store
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# Track failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Login state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Encryption key (static for simplicity)
def generate_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt
def encrypt_data(data, passkey):
    fernet = Fernet(generate_key(passkey))
    return fernet.encrypt(data.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    fernet = Fernet(generate_key(passkey))
    return fernet.decrypt(encrypted_text.encode()).decode()

# ============== Pages =================

def login_page():
    st.title("🔐 Login Required")
    user = st.text_input("Username")
    pw = st.text_input("Password", type="password")
    if st.button("Login"):
        if user == "admin" and pw == "admin123":  # Hardcoded for now
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials.")

def home():
    st.title("🛡️ Secure Data Vault")
    st.write("Choose an action:")
    if st.button("➕ Store Data"):
        st.session_state.page = "store"
    if st.button("🔓 Retrieve Data"):
        st.session_state.page = "retrieve"

def store_data_page():
    st.title("➕ Store Secure Data")
    key = st.text_input("Enter a unique data key (e.g., user1_data)")
    text = st.text_area("Enter your secret message")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Store"):
        if key in st.session_state.stored_data:
            st.warning("Key already exists! Choose another.")
        else:
            encrypted = encrypt_data(text, passkey)
            hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()
            st.session_state.stored_data[key] = {
                "encrypted_text": encrypted,
                "passkey": hashed_passkey
            }
            st.success("Data stored securely.")

    if st.button("⬅ Back"):
        st.session_state.page = "home"

def retrieve_data_page():
    st.title("🔓 Retrieve Data")
    key = st.text_input("Enter data key to retrieve")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Retrieve"):
        if key not in st.session_state.stored_data:
            st.error("Key not found.")
        else:
            stored = st.session_state.stored_data[key]
            hashed_input = hashlib.sha256(passkey.encode()).hexdigest()
            if hashed_input == stored["passkey"]:
                decrypted = decrypt_data(stored["encrypted_text"], passkey)
                st.success("✅ Data Decrypted:")
                st.code(decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey. Attempts: {st.session_state.failed_attempts}/3")

    if st.session_state.failed_attempts >= 3:
        st.session_state.authenticated = False
        st.warning("Too many failed attempts. Please login again.")
        st.session_state.page = "login"

    if st.button("⬅ Back"):
        st.session_state.page = "home"

# =========== Router ===========

def run_app():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    if not st.session_state.authenticated:
        login_page()
        return

    if st.session_state.page == "home":
        home()
    elif st.session_state.page == "store":
        store_data_page()
    elif st.session_state.page == "retrieve":
        retrieve_data_page()
    elif st.session_state.page == "login":
        login_page()

run_app()
