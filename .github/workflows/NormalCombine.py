import os
import json
import pandas as pd
import shutil
from datetime import datetime

# Define file paths
csv_folder = r"DatasetMaking\NormalOutput\rem_combine"
combined_file = r'DatasetMaking\NormalCSV\Normal_combined_features.csv'
# flow_tracker_file = "/media/harikrishna/E692008B92006303/Hari_Krishna_Khuju/MajorProject/Dataset/NewDataset/last_flow_number.json"
combined_output_folder = r"DatasetMaking\NormalOutput\combined"

# Create combined_output folder if it doesn't exist
os.makedirs(combined_output_folder, exist_ok=True)

# Columns to check for zero values
columns_to_check = [
    "duration", "avg_duration", "duration_std_dev", "percent_std_dev"
]

# # Load the last flow number from JSON file
# if os.path.exists(flow_tracker_file):
#     with open(flow_tracker_file, "r") as json_file:
#         flow_tracker = json.load(json_file)
#         last_flow_number = flow_tracker.get("last_flow_number", 0)
# else:
#     last_flow_number = 0  # Start from 0 if no JSON file exists   

# Load the existing combined features file, or initialize an empty DataFrame
if os.path.exists(combined_file):
    combined_df = pd.read_csv(combined_file)
else:
    combined_df = pd.DataFrame()  # Empty DataFrame if the combined file doesn't exist

# Start the flow number counter
# flow_number_counter = last_flow_number + 1

# Iterate over all files in the folder
for file_name in os.listdir(csv_folder):
    if file_name.endswith(".csv"):  # Process only CSV files
        file_path = os.path.join(csv_folder, file_name)
        print(f"Processing {file_name}...")
        df = pd.read_csv(file_path)

        # Remove rows where all specified columns are zero
        df = df[~(df[columns_to_check] == 0).all(axis=1)]

        # # Update flow numbers
        # num_rows = len(df)
        # df['flow_number'] = range(flow_number_counter, flow_number_counter + num_rows)

        # # Increment the counter
        # flow_number_counter += num_rows

        # Append the new data to the combined DataFrame
        combined_df = pd.concat([combined_df, df], ignore_index=True)

          # Check if the file already exists in the combined_output_folder
        new_file_path = os.path.join(combined_output_folder, file_name)
        if os.path.exists(new_file_path):
            # Generate a new name with a timestamp
            base_name, ext = os.path.splitext(file_name)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            new_file_name = f"{base_name}_{timestamp}{ext}"
            new_file_path = os.path.join(combined_output_folder, new_file_name)

        # Move the processed file to the combined_output folder with a new name if necessary
        shutil.move(file_path, new_file_path)
        print(f"Moved {file_name} to {new_file_path}")


# Save the updated combined DataFrame to the CSV file
combined_df.to_csv(combined_file, index=False)
print(f"Updated combined CSV saved to {combined_file}")

# # Update the JSON file with the latest flow number
# with open(flow_tracker_file, "w") as json_file:
#     json.dump({"last_flow_number": flow_number_counter - 1}, json_file)
# print(f"Flow tracker updated in {flow_tracker_file}")
