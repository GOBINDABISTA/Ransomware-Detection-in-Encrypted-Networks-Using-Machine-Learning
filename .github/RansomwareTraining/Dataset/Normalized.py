import pandas as pd
from sklearn.preprocessing import MinMaxScaler

# Load the dataset
csv_path = r'RansomwareTraining\Dataset\FinalDataset.csv'
data = pd.read_csv(csv_path)

# Define features for normalization (excluding non-numeric columns like labels)
features = [
    'duration', 'avg_duration', 'duration_std_dev', 'percent_std_dev', 'orig_payload_size',
    'resp_payload_size', 'payload_ratio',
    'inbound_packets', 'outbound_packets', 'avg_periodicity', 'periodicity_std',
    'ssl_flow_ratio', 'ssl_tls_ratio'
]

# Normalize the features to a range of 0 to 1
scaler = MinMaxScaler()
data[features] = scaler.fit_transform(data[features])

# Save the normalized dataset to a new CSV file
output_csv_path = r'RansomwareTraining\Dataset\FinalDataset_Normalized_features_minmax.csv'
data.to_csv(output_csv_path, index=False)

print(f"Normalized dataset saved to {output_csv_path}")
