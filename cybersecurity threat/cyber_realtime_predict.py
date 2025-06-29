import joblib
import numpy as np
import pandas as pd

# Load trained model and scaler
model = joblib.load("cyber_model.pkl")
scaler = joblib.load("scaler.pkl")
print(" Model and scaler loaded!")

# Sample input — must be 41 features
input_data = [0, 1, 20, 9, 1000, 500, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 5, 3, 0.05, 0.03, 0.0, 0.0, 0.8, 0.2, 0.1,
              255, 255, 1.0, 0.0, 0.01, 0.0, 0.05, 0.0, 0.0 ,0.0]

# Create DataFrame with matching columns
input_columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

input_df = pd.DataFrame([input_data], columns=input_columns)


# Transform using saved scaler
input_scaled = scaler.transform(input_df)

# Predict
prediction = model.predict(input_scaled)[0]

if prediction == 0:
    print("Prediction: Normal traffic")
else:
    print("Prediction: Malicious attack detected!")




