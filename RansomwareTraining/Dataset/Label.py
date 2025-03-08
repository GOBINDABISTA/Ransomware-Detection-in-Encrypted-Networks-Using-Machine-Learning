import pandas as pd
from sklearn.ensemble import IsolationForest

# Load your dataset (replace with your actual dataset file)
df = pd.read_csv(r'DatasetMaking\RansomwareCSV\combined_Rans_features.csv')

# Check if the relevant columns exist in the dataset
print("Columns in dataset:", df.columns)

# Select relevant features for anomaly detection (excluding flow_number, Label, and IP/port/protocol columns)
features = df.drop([ 'source_ip', 'dest_ip', 'source_port', 'dest_port','proto'], axis=1)

# Ensure all selected features are numeric
features = features.apply(pd.to_numeric, errors='coerce')

# # Check for missing values and handle them (either drop or fill)
# print("Missing values in features:", features.isnull().sum())
# features = features.fillna(features.mean())  # Replace missing values with column mean


# Ensure previously labeled "Ransomware" entries are not overwritten
# df['Label'] = df.apply(lambda row: row['Label'] if row['Label'] == 'Ransomware' else ('Ransomware' if row['anomaly'] == -1 else 'Normal'), axis=1)

# Create 'Label1' based on 'anomaly' values
df['Label'] = df.apply(lambda row : 'Ransomware', axis=1)


# Save the updated DataFrame to a new CSV file
df.to_csv(r'DatasetMaking\RansomwareCSV\Labeled_combined_Rans_features.csv', index=False)

