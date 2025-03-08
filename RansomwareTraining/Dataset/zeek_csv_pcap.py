import os
import shutil
import glob
import subprocess
import pandas as pd
import numpy as np
from scapy.all import rdpcap
import csv
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from config import configuration


# Path to your PCAP files and Zeek binary
pcap_dir = configuration.get('MainPcap_dir')  # Replace with the path to your PCAP files
output_dir = configuration.get('zeek_logs')   # Replace with the path to your output directory
zeek_bin = configuration.get('zeek_bin')


# Function to convert a log file to a CSV file
def convert_log_to_csv(log_file, csv_file):
    with open(log_file, 'r') as file:
        # Extract headers (skip commented lines)
        lines = file.readlines()
        data_start_index = 0
        for i, line in enumerate(lines):
            if not line.startswith("#"):
                data_start_index = i
                break
            if line.startswith("#fields"):
                headers = line.strip().split("\t")[1:]
        
        # Read the log as a DataFrame and filter out lines starting with `#`
        data = [line.strip().split("\t") for line in lines[data_start_index:] if not line.startswith("#")]
        df = pd.DataFrame(data, columns=headers)

    # Save as CSV
    df.to_csv(csv_file, index=False)
    print(f"Converted {log_file} to {csv_file}")

def No_duration(In_file_path):
            # Load conn.csv
        file_path = os.path.join(In_file_path, "conn.csv")  # Replace with the actual path to your conn.csv
        conn_data = pd.read_csv(file_path)

        # Display initial row count
        print(f"Initial number of rows: {conn_data.shape[0]}")

        # Identify rows where duration is NaN or empty
        condition1 = conn_data['duration'].isnull() | (conn_data['duration'] == "")

        # Identify rows where ((resp_pkts = 1 and orig_pkts = 0) or (resp_pkts = 0 and orig_pkts = 1))
        condition2 = (
            ((conn_data['resp_pkts'] == 1) & (conn_data['orig_pkts'] == 0)) |
            ((conn_data['resp_pkts'] == 0) & (conn_data['orig_pkts'] == 1))
        )

        # Combine conditions with logical AND
        rows_to_remove = condition1 & condition2

        # Remove the rows
        filtered_data = conn_data[~rows_to_remove]

        # Display final row count
        print(f"Number of rows after filtering: {filtered_data.shape[0]}")

        # Save the filtered data back to a CSV
        filtered_data.to_csv(file_path, index=False)  # Update path if needed
        print("Filtered data saved to 'conn.csv'")



def check_pcap_size(pcap_file, max_size_mb=200):
    try:
        # Get the file size in bytes
        file_size_bytes = os.path.getsize(pcap_file)
        # Convert the size to megabytes
        file_size_mb = file_size_bytes / (1024 * 1024)
        print(f"File size: {file_size_mb:.2f} MB")
        
        # Check if the size exceeds the maximum allowed
        if file_size_mb > max_size_mb:
            print(f"File size exceeds {max_size_mb} MB. Consider splitting the PCAP file.")
            return False
        return True
    except Exception as e:
        print(f"Error checking file size: {e}")
        return False



def split_pcap(input_pcap, output_dir, chunk_size_mb=200):
    os.makedirs(output_dir, exist_ok=True)
    
    # Split the pcap using editcap
    split_cmd = [
        'editcap', '-c', str(chunk_size_mb * 1024), 
        input_pcap, os.path.join(output_dir, 'split_part.pcap')
    ]
    try:
        subprocess.run(split_cmd, check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        print(f"PCAP file {input_pcap} split into smaller parts successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while splitting {input_pcap}: {e.stderr}")
        raise



def process_split_pcap_files(split_pcap_dir):
    # Identify all split PCAP files
    split_pcap_files = sorted(glob.glob(os.path.join(split_pcap_dir, '*.pcap')))
    
    for pcap_file in split_pcap_files:
        # Define the output CSV file name based on the PCAP file name
        output_csv = os.path.join(split_pcap_dir, os.path.basename(pcap_file) + '.csv')
        print(f"Processing file: {pcap_file}")
        # Extract packet details for each split PCAP file
        extract_packet_details(pcap_file, output_csv)


def combine_csv_files(csv_dir, output_csv):
    # Identify all CSV files in the directory
    csv_files = sorted(glob.glob(os.path.join(csv_dir, '*.csv')))
    
    combined_df = pd.DataFrame()  # Initialize an empty DataFrame
    
    # Iterate through each CSV file and append its content to the combined DataFrame
    for csv_file in csv_files:
        print(f"Reading CSV file: {csv_file}")
        df = pd.read_csv(csv_file)  # Read the CSV into a DataFrame
        combined_df = pd.concat([combined_df, df], ignore_index=True)  # Concatenate to the combined DataFrame
    
    # Save the combined DataFrame to a new CSV file
    combined_df.to_csv(output_csv, index=False)
    print(f"Combined CSV saved as: {output_csv}")


"""" Using rdPcap """

def extract_packet_details(pcap_file, output_csv):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Failed to read PCAP file: {e}")
        return

    packet_details = []

    for packet in packets:
        try:
            # Extract timestamp
            timestamp = packet.time

            # Extract source IP, destination IP, source port, destination port, and protocol
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = dst_ip = None

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = 'TCP'
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'UDP'
            else:
                src_port = dst_port = None
                protocol = None

            # Enhanced SSL/TLS detection logic
            ssl_tls_present = 0
            tls_present = 0
            if packet.haslayer('Raw'):
                raw_data = bytes(packet['Raw'].load)
                if len(raw_data) > 0 and raw_data[0] in [0x14, 0x15, 0x16, 0x17]:
                    ssl_tls_present = 1
                if len(raw_data) > 2 and raw_data[1:3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03', b'\x03\x04']:
                    tls_present = 1

            # Append the details to the list
            packet_details.append([timestamp, src_ip, src_port, dst_ip, dst_port, protocol, ssl_tls_present, tls_present])

        except IndexError as e:
            print(f"Skipping malformed packet: {e}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    # Save packet details to a CSV file
    try:
        with open(output_csv, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'SSL/TLS_Present', 'TLS_Present'])
            for details in packet_details:
                csv_writer.writerow(details)
        print(f"Packet details saved to {output_csv}")
    except Exception as e:
        print(f"Failed to save output CSV: {e}")


# Function to replace missing values '-' with NaN in a CSV file
def replace_missing_with_nan(csv_file):
    try:
        df = pd.read_csv(csv_file)
        df.replace('-', np.nan, inplace=True)
        df.to_csv(csv_file, index=False)
        print(f"Replaced missing values in {csv_file}")
    except Exception as e:
        print(f"Failed to replace missing values in {csv_file}: {e}")


# Ensure the output directory exists
os.makedirs(output_dir, exist_ok=True)

# Loop through each PCAP file
for pcap_file in os.listdir(pcap_dir):
    if pcap_file.endswith(".pcap"):
        # Create a subfolder in the output directory for each PCAP file
        folder_name = os.path.join(output_dir, pcap_file.replace(".pcap", ""))
        
        # Check if the folder already exists
        if os.path.exists(folder_name):
            print(f"Skipping {pcap_file}, folder {folder_name} already exists.")
            continue  # Skip to the next file

        # Create the folder if it doesn't exist
        os.makedirs(folder_name, exist_ok=True)

        # Run Zeek on the PCAP file, saving the logs to the created subfolder
        pcap_path = os.path.join(pcap_dir, pcap_file)
        shutil.copy(pcap_path, folder_name)

        command = [zeek_bin, "-r", pcap_path]
        subprocess.run(command, cwd=folder_name)

        print(f"Processed {pcap_file}, logs and PCAP stored in {folder_name}")


        # Convert generated log files to CSV
        for log_file in os.listdir(folder_name):
            if log_file.endswith(".log"):  # Process only .log files
                log_path = os.path.join(folder_name, log_file)
                csv_path = os.path.join(folder_name, log_file.replace(".log", ".csv"))
                convert_log_to_csv(log_path, csv_path)
                replace_missing_with_nan(csv_path)

        
        # filter the conn.csv to filter out null duration values
        No_duration(folder_name)



        #Extract packet-level details and save as CSV
        packet_output_csv = os.path.join(folder_name, "pkt_details.csv")
        try:
            if check_pcap_size(pcap_path):
                extract_packet_details(pcap_path, packet_output_csv)
            else:
                print("splitting file processing due to size limit.")
                folder_output_dir = os.path.join(folder_name,"SplitPcap")
                os.makedirs(folder_output_dir, exist_ok=True)
                split_pcap(pcap_path, folder_output_dir)
                process_split_pcap_files(folder_output_dir)
                combine_csv_files(folder_output_dir, packet_output_csv)
                print(f"{folder_name}")

        except Exception as e:
            print(f"Failed to extract packet details for {pcap_file}: {e}")

    