import joblib
import sys
import os
import pandas as pd
from extractor import extract_pe_features

# To ignore the feature name warning
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

def scan(file_path):
    if not os.path.exists('malware_model.pkl'):
        print("Error: Train model first.")
        return
        
    model = joblib.load('malware_model.pkl')
    # Get features + entropy + hash
    features, entropy, f_hash = extract_pe_features(file_path)
    
    if features:
        # Convert to DataFrame to remove the Warning
        feature_names = [
            'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
            'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
            'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
            'ImageBase', 'SectionAlignment', 'FileAlignment'
        ]
        df_features = pd.DataFrame([features], columns=feature_names)
        
        prediction = model.predict(df_features)[0]
        confidence = model.predict_proba(df_features)[0]
        
        print("\n" + "🛡️  CROWDSTRIKE PROJECT: AI MALWARE SCANNER")
        print("="*60)
        print(f"FILE NAME : {os.path.basename(file_path)}")
        print(f"SHA-256   : {f_hash}")
        print(f"ENTROPY   : {entropy:.4f} (High > 7.0 is suspicious)")
        print("-" * 60)
        
        if prediction == 1:
            print(f"ML PREDICTION :  MALICIOUS")
            print(f"CONFIDENCE    : {confidence[1]*100:.2f}%")
        else:
            print(f"ML PREDICTION :  SAFE")
            print(f"CONFIDENCE    : {confidence[0]*100:.2f}%")
        print("="*60 + "\n")
    else:
        print("Analysis Failed.")

if __name__ == "__main__":
    if len(sys.argv) > 1: scan(sys.argv[1])
    else: print("Usage: python scanner.py <path_to_exe>")