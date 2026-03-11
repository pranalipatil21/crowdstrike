import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import matplotlib.pyplot as plt
import numpy as np

# 1. Load Dataset
df = pd.read_csv('dataset/dataset_malwares.csv')

# 2. Select specific PE features
used_features = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
    'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
    'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'ImageBase', 'SectionAlignment', 'FileAlignment'
]

X = df[used_features]
y = df['Malware']

# 3. Train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Save
print(f"Accuracy: {accuracy_score(y_test, model.predict(X_test))*100:.2f}%")
joblib.dump(model, 'malware_model.pkl')
print("Model saved to virtual environment folder.")




importances = model.feature_importances_
indices = np.argsort(importances)

plt.figure(figsize=(10,6))
plt.title('Feature Importances in Malware Detection')
plt.barh(range(len(indices)), importances[indices], align='center')
plt.yticks(range(len(indices)), [used_features[i] for i in indices])
plt.xlabel('Relative Importance')
plt.show()