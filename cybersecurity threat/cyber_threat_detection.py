import pandas as pd
import numpy as np

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
print(" Starting cybersecurity threat detection script...")

# Set plot style (optional, for better visuals later)
sns.set(style="whitegrid")

# Load training and testing data

try:
    train_df = pd.read_csv("dataset/KDDTrain+.txt", header=None)
    test_df = pd.read_csv("dataset/KDDTest+.txt", header=None)
    
    print("Dataset loaded successfully!")
    print("Training data shape:", train_df.shape)
    print("Testing data shape:", test_df.shape)
    print("\n Preview of Training Data:")
    print(train_df.head())
except FileNotFoundError:
    print("File not found. Please make sure the dataset folder and filenames are correct.")

#Adding Column Names

columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

train_df.columns = columns
test_df.columns = columns

# Drop 'difficulty' column
train_df.drop('difficulty', axis=1, inplace=True)
test_df.drop('difficulty', axis=1, inplace=True)

#Encode Categorical Features

from sklearn.preprocessing import LabelEncoder

combined = pd.concat([train_df, test_df])
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    combined[col] = le.fit_transform(combined[col])

# Split combined data back
train_df = combined.iloc[:len(train_df), :]
test_df = combined.iloc[len(train_df):, :]

#Scale and Prepare Features

scaler = StandardScaler()

X_train = train_df.drop('label', axis=1)
X_test = test_df.drop('label', axis=1)

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Binary classification: normal = 0, attack = 1
y_train = train_df['label'].apply(lambda x: 0 if x == 'normal' else 1)
y_test = test_df['label'].apply(lambda x: 0 if x == 'normal' else 1)

#Training Random Forest Classifier 

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train_scaled, y_train)

y_pred = clf.predict(X_test_scaled)

#Evaluate the Model

print("\n Accuracy:", accuracy_score(y_test, y_pred))

print("\n Classification Report:\n")
print(classification_report(y_test, y_pred))

print("\n Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()
#tuning for random forest algorithm
clf = RandomForestClassifier(n_estimators=200, max_depth=20, class_weight='balanced')
#handling class imbalance
clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
#tuning hyperparameters
clf = RandomForestClassifier(n_estimators=200, max_depth=25, class_weight='balanced', random_state=42)
class_weight='balanced'

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    class_weight='balanced',
    min_samples_leaf=4,
    random_state=42
)

from sklearn.ensemble import RandomForestClassifier

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    min_samples_leaf=4,
    class_weight='balanced',
    random_state=42
)
# Define y_train_binary
y_train_binary = train_df['label'].apply(lambda x: 0 if x == 'normal' else 1)
clf.fit(X_train_scaled, y_train_binary)

import matplotlib.pyplot as plt

importances = clf.feature_importances_
features = train_df.drop('label', axis=1).columns

import joblib

# Save trained model and scaler
joblib.dump(clf, "cyber_model.pkl")
joblib.dump(scaler, "scaler.pkl")
print(" Model and scaler saved successfully.")
