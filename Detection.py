import os
import joblib
import nest_asyncio
import psutil
import pandas as pd
import numpy as np
import time
from scapy.all import sniff, IP, TCP, UDP, Raw
import socket
from sklearn.preprocessing import MinMaxScaler
import sklearn
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb



# Apply nest_asyncio to prevent asyncio issues in some environments
nest_asyncio.apply()

flows = {}

# Load trained models
model_path = r"RansomwareTraining\models"
# model_path = r"C:\GB\MajorProject\Dataset\NewDataset\ransomwareTraining\models"
rf_model = joblib.load(os.path.join(model_path, "random_forest_New.pkl"))
xgb_model = joblib.load(os.path.join(model_path, "xgboost_New.pkl"))
dt_model = joblib.load(os.path.join(model_path, "decision_tree_New.pkl"))

def get_local_ip():
    # Get the local machine's IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # Connect to an external server (doesn't actually connect)
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'  # fallback to localhost IP if no network is available
    finally:
        s.close()
    return ip


def get_active_interface():
    """Returns the first active network interface (excluding loopback)."""
    interfaces = psutil.net_if_addrs()
    print("Available Interfaces:", interfaces)
    
    for interface in interfaces:
        if interface != 'lo':  # Ignore loopback
            return interface  # Return the first active interface

    return None  # No active interface found


def process_flow_with_duration(flow_data):
    # Assuming flow_data['duration'] contains the list of durations (e.g., [0.0, 0.0039, 0.0040, ...])
    df_packet = flow_data['duration']  # Your 'duration' list of packet durations

    # Step 1: Calculate the first differences (packet durations diff)
    first_diff = np.diff(df_packet)  # Calculate differences between consecutive durations
    
    # Step 2: Take absolute values of the first differences
    abs_first_diff = np.abs(first_diff)
    
    # Step 3: Calculate the second differences (diff of abs_first_diff)
    second_diff = np.diff(abs_first_diff)
    
    # Step 4: Take absolute values of the second differences
    abs_second_diff = np.abs(second_diff)
    
    # Step 5: Calculate periodicity (mean of absolute second differences)
    non_zero_second_diff = abs_second_diff[abs_second_diff != 0]  # Remove zeros for accurate mean
    periodicity = np.mean(non_zero_second_diff) if len(non_zero_second_diff) > 0 else 0
    
    # Step 6: Calculate periodicity standard deviation
    if len(non_zero_second_diff) > 0:
        periodicity_std = np.std(non_zero_second_diff)
    else:
        periodicity_std = 0

    return periodicity, periodicity_std


def normalize_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """Normalize the flow key to treat both directions as the same."""
    # Sort IPs and ports to ensure the same flow in both directions
    ip_pair = tuple(sorted([src_ip, dst_ip]))
    port_pair = tuple(sorted([src_port, dst_port]))

    # Return the normalized flow key
    return (ip_pair[0], ip_pair[1], port_pair[0], port_pair[1], protocol)

def process_packet(packet):
    """Extracts network packet details and predicts using trained models."""

    # Remove expired flows before processing new packets
    # remove_old_flows()
    global flows
    try:
        # Extract timestamp
        timestamp = packet.time

        # Extract source IP, destination IP, source port, destination port, and protocol
        src_ip, dst_ip, src_port, dst_port, protocol = None, None, None, None, None

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'

        # Enhanced SSL/TLS detection logic
        ssl_tls_present = 0
        tls_present = 0
        payload_length = 0
        

        if packet.haslayer(Raw):
            payload_length = len(packet[Raw].load)
            raw_data = bytes(packet[Raw].load)
            if raw_data and raw_data[0] in [0x14, 0x15, 0x16, 0x17]:  # SSL/TLS Content Type
                ssl_tls_present = 1
            if len(raw_data) > 2 and raw_data[1:3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03', b'\x03\x04']:  # TLS Versions
                tls_present = 1

        # Ensure we have valid IP and port values
        if src_ip and dst_ip and src_port and dst_port and protocol:
            flow_key = normalize_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            # Non-normalized flow key (original IPs and ports)
            flow_key_non_normalized = (src_ip, dst_ip, src_port, dst_port, protocol)
            # print(f"Flow Key:  {flow_key}")

            # If flow already exists, update the flow
            if flow_key in flows:
                flow = flows[flow_key]
                if not (local_ip == flow_key_non_normalized[0]):
                    # in_pkt  = 1
                    flow['resp_payload_size'] += payload_length
                    flow['inbound_packets'] += 1
                    # print(f"Inbound_packet {in_pkt}")
                else:
                    # out_pkt = 0
                    flow['orig_payload_size'] += payload_length
                    flow['outbound_packets'] += 1
                    # print(f"Outbound_packet {out_pkt}")

                # print(f"flow {flow}")
                # print(f"flow_key_non_normalized{flow_key_non_normalized}")
                flow['packets'] += 1
                new_duration = time.time()
                flow['duration'].append(new_duration - flow['last_updated'])  # Update duration
                flow['last_updated'] = new_duration  # Update timestamp of the last packet
                # durations = flow['duration']
                # print(f"flowdurationlen {len(durations)}")
                flow['payload_ratio'] = flows[flow_key]['resp_payload_size'] / flows[flow_key]['orig_payload_size'] if flows[flow_key]['orig_payload_size'] != 0 else 0
                flow['tls_present'] += tls_present
                flow['ssl_tls_present'] += ssl_tls_present
                non_ssl_count = flow['packets'] - flow['ssl_tls_present']
                flow['ssl_tls_ratio']  = flow['tls_present'] / flow['ssl_tls_present'] if flow['ssl_tls_present'] > 0 else 0
                flow['ssl_flow_ratio']  = flow['ssl_tls_present'] / non_ssl_count if non_ssl_count > 0 else 0

            else:
                # Create a new flow entry
                resp_payload = 0
                orig_payload = 0
                outbound_pkt = 0
                inbound_pkt = 0

                if local_ip != flow_key_non_normalized[0]:
                    # in_pkt  = 1
                    resp_payload = payload_length
                    inbound_pkt = 1
                    # print(f"Inbound_packet {in_pkt}")
                else:
                    # out_pkt = 0
                    orig_payload = payload_length
                    outbound_pkt = 1
                    # print(f"Outbound_packet {out_pkt}")

                flows[flow_key] = {
                    "packets": 1,
                    # "start_time": time.time(),
                    "last_updated": time.time(),
                    "duration": [0.],  # Initial duration is 0
                    "inbound_packets": inbound_pkt,  # Inbound packet counter
                    "outbound_packets": outbound_pkt,  # Outbound packet counter
                    "orig_payload_size": orig_payload,  # Initialize payload size
                    "resp_payload_size": resp_payload,
                    "payload_ratio": 0,
                    "ssl_tls_present": ssl_tls_present,
                    "tls_present" : tls_present,
                    "ssl_tls_ratio" : 0,
                    "ssl_flow_ratio" :0, 
                }

        # Print extracted details
        print(f"Timestamp: {timestamp}")
        print(f"Source IP: {src_ip}, Source Port: {src_port}")
        print(f"Destination IP: {dst_ip}, Destination Port: {dst_port}")
        print(f"Protocol: {protocol}")
        print(f"SSL/TLS Present: {ssl_tls_present}, TLS Version Detected: {tls_present}")
        print("-" * 50)

    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Local IP Address: {local_ip}")
    print("Capturing 4 live packets...\n")
    sniff(prn=process_packet, count=500, filter="ip", store=False)
    print(f"All flows are: ")
    print(flows)

    # Flatten the flows data
    flattened_data = []
    for flow_key, flow_value in flows.items():
        # # Ensure duration is updated from the flow
        duration = flow_value['duration']

        duration_sum = sum(duration)

        avg_duration = sum(duration) / len(duration) if duration else 0
        # Calculate duration_std_dev (Fix: Use correct list referencing)
        if len(duration) > 1:
            mean_dur = avg_duration
            duration_std_dev = (sum((x - mean_dur) ** 2 for x in duration) / len(duration)) ** 0.5
        else:
            duration_std_dev = 0  # No variation with only one duration

        # Calculate percent_std_dev (Fix: Ensure avg_duration is not zero)
        percent_std_dev = (duration_std_dev / avg_duration) * 1 if avg_duration != 0 else 0 

        avg_periodicity, periodicity_std =process_flow_with_duration(flow_value)

        flow_data = {
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'src_port': flow_key[2],
            'dst_port': flow_key[3],
            'proto': flow_key[4],
            'duration': duration_sum,
            'avg_duration': avg_duration,
            'duration_std_dev': duration_std_dev,
            'dur_percent_std_dev' : percent_std_dev,
            # 'orig_payload_size': flow_value['orig_payload_size'],
            'resp_payload_size': flow_value['resp_payload_size'],
            'payload_ratio': flow_value['payload_ratio'],
            # 'inbound_packets': flow_value['inbound_packets'],
            'outbound_packets': flow_value['outbound_packets'],
            'avg_periodicity' : avg_periodicity,
            'periodicity_std': periodicity_std,
            'ssl_flow_ratio': flow_value['ssl_flow_ratio'],
            'ssl_tls_ratio': flow_value['ssl_tls_ratio']
        }
        flattened_data.append(flow_data)


    # Convert flattened_data into a DataFrame
    df = pd.DataFrame(flattened_data)
    # columns=['duration', 'avg_duration', 'duration_std_dev', 'percent_std_dev', 'orig_payload_size','resp_payload_size', 'payload_ratio', 'inbound_packets', 'outbound_packets', 'avg_periodicity', 'periodicity_std', 'ssl_flow_ratio','ssl_tls_ratio']
    columns=['duration', 'avg_duration', 'duration_std_dev', 'dur_percent_std_dev','resp_payload_size', 'payload_ratio','outbound_packets', 'avg_periodicity', 'periodicity_std', 'ssl_flow_ratio','ssl_tls_ratio']
    # Extract feature data for predictions
    feature_data = df[columns]


    print(f"Actual No of Flows {len(flows)}")
    # Loop through each flow in the dataset and make predictions
    for index, row in feature_data.iterrows():
        row_data = pd.DataFrame([row], columns=columns)
        
        # Get prediction probabilities
        rf_proba = rf_model.predict_proba(row_data)[0]
        xgb_proba = xgb_model.predict_proba(row_data)[0]
        dt_proba = dt_model.predict_proba(row_data)[0]

        # Extract probabilities for both classes (0: Normal, 1: Ransomware)
        rf_confidence_normal, rf_confidence_ransomware = rf_proba
        xgb_confidence_normal, xgb_confidence_ransomware = xgb_proba
        dt_confidence_normal, dt_confidence_ransomware = dt_proba

        # Get predicted class and map 0/1 to labels
        rf_pred = "Normal" if rf_confidence_ransomware < 0.6 else "Ransomware"
        xgb_pred = "Normal" if xgb_confidence_ransomware < 0.6 else "Ransomware"
        dt_pred = "Normal" if dt_confidence_ransomware < 0.6 else "Ransomware"

        # Print results for each flow
        print(f"--------------------------------------------------")
        print(f"Flow {index+1}: {df.iloc[index]['src_ip']} -> {df.iloc[index]['dst_ip']} ({df.iloc[index]['proto']})")
        print(f"Random Forest Prediction: (Normal: {rf_confidence_normal:.4f}, Ransomware: {rf_confidence_ransomware:.4f}) --->> {rf_pred}")
        print(f"XGBoost Prediction: (Normal: {xgb_confidence_normal:.4f}, Ransomware: {xgb_confidence_ransomware:.4f}) --->> {xgb_pred}")
        print(f"Decision Tree Prediction: (Normal: {dt_confidence_normal:.4f}, Ransomware: {dt_confidence_ransomware:.4f}) --->> {dt_pred}")
        print(f"============================================================")
    

    print("\nCapture Complete!")
