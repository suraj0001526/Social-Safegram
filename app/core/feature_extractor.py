import pefile
import os

def extract_features(file_path):
    """
    Extracts exactly 7 features from the PE file to match the trained model.
    """
    pe = None
    try:
        # 1. Open the PE file
        pe = pefile.PE(file_path)
        
        features = []
        
        # --- EXTRACT THE 7 KEY FEATURES ---
        # These are the standard 7 headers usually used in basic malware models
        features.append(pe.FILE_HEADER.Machine)
        features.append(pe.FILE_HEADER.SizeOfOptionalHeader)
        features.append(pe.FILE_HEADER.Characteristics)
        features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        features.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
        features.append(pe.OPTIONAL_HEADER.SizeOfCode)
        features.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)

        # 🛑 SAFETY CHECK: Ensure we send exactly 7 items
        # If for some reason we added too many, this chops it to 7.
        return features[:7]

    except Exception as e:
        print(f"Extraction Error: {e}")
        return None

    finally:
        # 🟢 CRITICAL: Close file so Windows can delete it later
        if pe:
            pe.close()