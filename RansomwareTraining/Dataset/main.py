import os
import sys
import subprocess
from config import configuration
from Features_flow import  process_folder, move_to_completed
from data_features import Features_extraction

def get_folders_to_process(base_path, completed_path, batch_size):
    """Get a batch of folders from zeek_logs that are not yet completed."""
    all_folders = [f for f in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, f))]
    completed_folders = [f for f in os.listdir(completed_path) if os.path.isdir(os.path.join(completed_path, f))]
    remaining_folders = [f for f in all_folders if f not in completed_folders]
    return remaining_folders[:batch_size]

def main():

    # Run the zeek_csv_pcap.py script
    zeek_csv_pcap_script = "zeek_csv_pcap.py"
    print(f"Running {zeek_csv_pcap_script}...")
    subprocess.run(["python3", zeek_csv_pcap_script], check=True)

    print("running main process")

    # Get folders to process in this batch
    folders_to_process = get_folders_to_process(configuration.get('zeek_logs'), configuration.get('completed_path'), configuration.get('batch_size'))
    # folders_to_process = get_folders_to_process(configuration.get('zeek_logs'), configuration.get('completed_path'), configuration.get('batch_size'))
    
    if not folders_to_process:
        print("No more folders to process.")
    
    for folder_name in folders_to_process:
        folder_path = os.path.join(configuration.get('zeek_logs'), folder_name)
        try:
            process_folder(folder_path, folder_name)  # Process the folder
            Features_extraction(configuration.get('Csv_path'), folder_name,folder_path)
            # Features_extraction(configuration.get('Csv_path'), folder_name,folder_path)
            move_to_completed(folder_name, configuration.get('zeek_logs'), configuration.get('completed_path'))  # Move to completed
        except Exception as e:
            print(f"Error processing {folder_name}: {e}")

    # Run the No_Zero_Combine.py script
    No_Zero_Combine = "No_Zero_Combine.py"
    print(f"Running {No_Zero_Combine}...")
    subprocess.run(["python3", No_Zero_Combine], check=True)

    # Run the Label.py script
    Label = "Label.py"
    print(f"Running {Label}...")
    subprocess.run(["python3", Label], check=True)

if __name__ == "__main__":
    print(sys.path)
    main()
