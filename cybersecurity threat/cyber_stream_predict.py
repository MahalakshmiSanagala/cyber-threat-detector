import pandas as pd
import joblib
import time

# Load model and scaler
model = joblib.load("cyber_model.pkl")
scaler = joblib.load("scaler.pkl")
print("Model and scaler loaded!")

# Column names in training order
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

# Read data with no header
df = pd.read_csv("sample_stream.csv", header=None, names=input_columns)

# Simulate real-time detection
for i, row in df.iterrows():
    input_df = pd.DataFrame([row.values], columns=input_columns)
    input_scaled = scaler.transform(input_df)

    prediction = model.predict(input_scaled)[0]

    print(f"\nRow {i+1}: ", end="")
    if prediction == 0:
        print("Normal traffic")
    else:
        print(" Malicious attack detected!")

    time.sleep(2)  # Simulate delay
