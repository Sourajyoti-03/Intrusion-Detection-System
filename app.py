import streamlit as st
import numpy as np
import pandas as pd
import joblib
import pymongo
from datetime import datetime
from pymongo import MongoClient
import hashlib
import os
from dotenv import load_dotenv
load_dotenv()  # This loads environment variables from the .env file
# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")
client = pymongo.MongoClient(MONGO_URI)
db = client["intrusion_detection"]
users_col = db["users"]
predictions_col = db["predictions"]

# Load model and scaler
model = joblib.load("best_final_model.pkl")
scaler = joblib.load("scaler.pkl")

# Session state for user
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.user_info = {}

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(username, password):
    user = users_col.find_one({"username": username})
    if user and user["password"] == hash_password(password):
        return user
    return None

# Page config
st.set_page_config(page_title="IDS App", layout="wide")

# Inject CSS
st.markdown("""
    <style>
        .stButton>button {background-color: #1e3a8a; color: white; border-radius: 8px;}
        .stButton>button:hover {background-color: #3b82f6;}
        .main {background-color: #f9fafb;}
    </style>
""", unsafe_allow_html=True)

# === LOGIN / SIGNUP PAGES ===
if not st.session_state.logged_in:
    st.image("Logo.png", width=200)
    page = st.sidebar.radio("Select Page", ["🔐 Login", "📝 Signup"])

    if page == "🔐 Login":
        st.markdown("<h2 style='color:#1e3a8a;'>🔐 Login</h2>", unsafe_allow_html=True)
        username = st.text_input("Username").strip()
        password = st.text_input("Password", type="password").strip()


        if st.button("Login"):
            user = verify_user(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.user_info = {
                    "email": user.get("email", ""),
                    "country": user.get("country", ""),
                    "city": user.get("city", "")
                }
                st.success(f"✅ Welcome back, {username}!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password.")

    elif page == "📝 Signup":
        st.markdown("<h2 style='color:#1e3a8a;'>📝 Signup</h2>", unsafe_allow_html=True)
        username = st.text_input("Choose Username").strip()
        email = st.text_input("Email").strip()
        password = st.text_input("Password", type="password").strip()
        confirm_password = st.text_input("Confirm Password", type="password").strip()
        country = st.text_input("Country").strip()
        city = st.text_input("City").strip()


        if st.button("Create Account"):
            if password != confirm_password:
                st.error("❌ Passwords do not match.")
            elif users_col.find_one({"username": username}):
                st.error("❌ Username already exists.")
            else:
                st.session_state.user_info = {"username": username, "email": email, "country": country, "city": city}
                users_col.insert_one({
                    "username": username,
                    "email": email,
                    "password": hash_password(password),
                    "country": country,
                    "city": city
                })
                st.success("✅ Account created! Please log in.")
else:
    # === SIDEBAR MENU ===
    st.sidebar.write(f"👋 Logged in as: **{st.session_state.username}**")
    menu = st.sidebar.radio("Dashboard Menu", ["🔍 Prediction", "📜 History"] + (["🔧 Admin Page"] if st.session_state.username == "admin" else []))

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.user_info = {}
        st.rerun()

    # === PREDICTION PAGE ===
    if menu == "🔍 Prediction":
        # Create two columns: one for the image, the other for the text
        col1, col2 = st.columns([1, 3])
        with col1:
            st.image("Logo.png", width=200)
        with col2:
            st.markdown("<h1 style='color:#1e3a8a;'>🔒 Intrusion Detection System</h1>", unsafe_allow_html=True)
        st.markdown("---")


        feature_names = [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
            "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
            "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
            "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
            "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
            "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
            "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
            "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
            "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
            "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
            "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std",
            "Idle Max", "Idle Min"
        ]

        input_mode = st.radio("Choose input method:", ["🔘 Comma-Separated Line", "🧾 Individual Fields"])
        inputs = []

        if input_mode == "🔘 Comma-Separated Line":
            user_input = st.text_area("Enter all 78 values (comma-separated)", height=150)
            if st.button("🔍 Predict Intrusion"):
                try:
                    values = list(map(float, user_input.strip().split(',')))
                    if len(values) != len(feature_names):
                        st.error(f"❌ Expected {len(feature_names)} values, but got {len(values)}.")
                    else:
                        df = pd.DataFrame([values], columns=feature_names)
                        df_scaled = scaler.transform(df)
                        prediction = model.predict(df_scaled)[0]
                        result = "Intrusion Detected" if prediction == 1 else "Normal Traffic"
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        st.success(f"✅ Prediction: **{result}**")
                        st.info(f"🕒 Timestamp: {timestamp}")

                        predictions_col.insert_one({
                            "username": st.session_state.username,
                            "email": st.session_state.user_info.get("email", ""),
                            "country": st.session_state.user_info.get("country", ""),
                            "city": st.session_state.user_info.get("city", ""),
                            "inputs": values,
                            "result": result,
                            "timestamp": timestamp
                        })
                except Exception as e:
                    st.error(f"⚠️ Error: {e}")

        elif input_mode == "🧾 Individual Fields":
            st.markdown("<h3 style='color:#1e3a8a;'>🔢 Input Features</h3>", unsafe_allow_html=True)
            cols = st.columns(3)
            for i, feature in enumerate(feature_names):
                with cols[i % 3]:
                    val = st.text_input(f"{feature}", key=feature)
                    try:
                        val = float(val)
                        inputs.append(val)
                    except:
                        inputs.append(None)

            if st.button("🔍 Predict Intrusion"):
                if None in inputs:
                    st.error("❌ Please fill in all fields with valid numbers.")
                else:
                    try:
                        df = pd.DataFrame([inputs], columns=feature_names)
                        df_scaled = scaler.transform(df)
                        prediction = model.predict(df_scaled)[0]
                        result = "Intrusion Detected" if prediction == 1 else "Normal Traffic"
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        st.success(f"✅ Prediction: **{result}**")
                        st.info(f"🕒 Timestamp: {timestamp}")

                        predictions_col.insert_one({
                            "username": st.session_state.username,
                            "email": st.session_state.user_info.get("email", ""),
                            "country": st.session_state.user_info.get("country", ""),
                            "city": st.session_state.user_info.get("city", ""),
                            "inputs": inputs,
                            "result": result,
                            "timestamp": timestamp
                        })
                    except Exception as e:
                        st.error(f"⚠️ Error during prediction: {e}")

    # === HISTORY PAGE ===
    elif menu == "📜 History":
        st.markdown("<h2 style='color:#1e3a8a;'>📜 Prediction History</h2>", unsafe_allow_html=True)
        history = list(predictions_col.find({"username": st.session_state.username}))
        if history:
            for doc in history:
                doc["inputs"] = ", ".join(map(str, doc.get("inputs", [])))  # 👈 fix for displaying list
            df = pd.DataFrame(history)
            df = df[["timestamp", "result", "inputs"]]
            st.dataframe(df)
        else:
            st.info("No prediction history found.")

    # === ADMIN PAGE ===
    elif menu == "🔧 Admin Page":
        st.markdown("<h2 style='color:#1e3a8a;'>🔧 Admin Page</h2>", unsafe_allow_html=True)
        st.write("Welcome, Admin. This section is only visible to administrators.")

        # Example content: list of registered users
        user_list = list(users_col.find({}, {"_id": 0, "username": 1, "email": 1, "country": 1, "city": 1}))
        if user_list:
            st.dataframe(pd.DataFrame(user_list))
        else:
            st.info("No users found.")

# Developer credit
st.markdown("""
    <div style='position: fixed; bottom: 10px; right: 10px; font-size: 12px; color: gray;'>
        Developed by <b>Sourajyoti Choudhury</b> | 📧 <a href='mailto:sourajyotichoudhury@gmail.com'>sourajyotichoudhury@gmail.com</a>
    </div>
""", unsafe_allow_html=True)
