import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# 1. Create Dummy Data (Synthetic Malware & Benign files)
# Features: [Machine, SizeOfOptionalHeader, Characteristics, MajorLinkerVersion, ImageBase, AvgEntropy, Imported_DLL_Count]
data = {
    'Machine': [332, 332, 34404, 332, 34404],
    'SizeOfOptionalHeader': [224, 224, 240, 224, 240],
    'Characteristics': [8450, 258, 34, 8450, 258],
    'MajorLinkerVersion': [8, 9, 14, 6, 10],
    'ImageBase': [4194304, 268435456, 4194304, 16777216, 4194304],
    'AvgEntropy': [6.5, 3.2, 7.8, 4.1, 7.9], # High entropy often indicates malware (packed)
    'Imported_DLL_Count': [5, 12, 1, 15, 2],
    'is_malware': [1, 0, 1, 0, 1] # 1 = Malware, 0 = Safe
}

df = pd.DataFrame(data)

# 2. Separate Features (X) and Labels (y)
X = df.drop('is_malware', axis=1)
y = df['is_malware']

# 3. Train the Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# 4. Save the Model
save_path = os.path.join(os.path.dirname(__file__), "malware_model.pkl")
joblib.dump(model, save_path)

print(f"✅ Dummy Model trained and saved to: {save_path}")