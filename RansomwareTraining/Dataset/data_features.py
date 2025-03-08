import pandas as pd
import numpy as np
from decimal import Decimal

from scapy.all import * 
import ipaddress
import struct
from collections import defaultdict

from config import configuration


def Features_extraction(output_file_p, folder_name, folder_path):
    print("feature_extraction")
    print(f"outputfile: {output_file_p}")
    print(f"folder_name: {folder_name}")
    print(f"folder_path: {folder_path}")
    packet_details_file = os.path.join(folder_path,"pkt_details.csv")
    pkt_detail_df = pd.read_csv(packet_details_file)

    def extract_packet_durations(pkt_detail_df, src_ip_filter=None, dest_ip_filter=None, src_port_filter=None, dest_port_filter=None, proto=None):
        # Dictionaries and counters
        total_pkt_count = 0
        ssl_tls_total = 0
        tls_count = 0
        non_ssl_count = 0

        # Filter rows based on matching criteria
        filtered_df1 = pkt_detail_df[(pkt_detail_df['Source IP'] == src_ip_filter) &
                        (pkt_detail_df['Source Port'] == src_port_filter) &
                        (pkt_detail_df['Destination IP'] == dest_ip_filter) &
                        (pkt_detail_df['Destination Port'] == dest_port_filter) &
                        (pkt_detail_df['Protocol'].str.upper() == proto)]

        # Check if 'Outbound_Packet' exists, if not create it
        if 'Outbound_Packet' not in filtered_df1.columns:
            filtered_df1['Outbound_Packet'] = 0

        # Check if 'Inbound_Packet' exists, if not create it
        if 'Inbound_Packet' not in filtered_df1.columns:
            filtered_df1['Inbound_Packet'] = 0
        # Add columns for filtered_df1
        filtered_df1['Outbound_Packet'] = 1
        filtered_df1['Inbound_Packet'] = 0

        filtered_df1 = filtered_df1.dropna()
        
        filtered_df2 = pkt_detail_df[(pkt_detail_df['Source IP'] == dest_ip_filter) &
                        (pkt_detail_df['Source Port'] == dest_port_filter) &
                        (pkt_detail_df['Destination IP'] == src_ip_filter) &
                        (pkt_detail_df['Destination Port'] == src_port_filter) &
                        (pkt_detail_df['Protocol'].str.upper() == proto)]
        
         # Check if 'Outbound_Packet' exists, if not create it
        if 'Outbound_Packet' not in filtered_df2.columns:
            filtered_df2['Outbound_Packet'] = 0

        # Check if 'Inbound_Packet' exists, if not create it
        if 'Inbound_Packet' not in filtered_df2.columns:
            filtered_df2['Inbound_Packet'] = 0

        # Add columns for filtered_df2
        filtered_df2['Outbound_Packet'] = 0
        filtered_df2['Inbound_Packet'] = 1
        filtered_df2 = filtered_df2.dropna()


        # Concatenate both dataframes into one
        filtered_df = pd.concat([filtered_df1, filtered_df2])

        # Sort by timestamp in ascending order
        filtered_df = filtered_df.sort_values(by='Timestamp', ascending=True).reset_index(drop=True)

        filtered_df.loc[0, 'pkt_duration'] = 0
        # Calculate the duration without modifying the original 'Timestamp' column
        duration = filtered_df['Timestamp']
        filtered_df['pkt_duration'] = duration.diff()
        filtered_df.loc[0, 'pkt_duration'] = 0

        # Display the filtered dataframe
        print(filtered_df)

        total_pkt_count = len(filtered_df)
        ssl_tls_total = filtered_df['SSL/TLS_Present'].sum()
        tls_count = filtered_df['TLS_Present'].sum()

        # Save the filtered rows to a new CSV file
        # filtered_df.to_csv( os.path.join(folder_path, "filtered_pkt_detail.csv"), index=False, sep='\t')
        

        non_ssl_count = total_pkt_count - ssl_tls_total
        ssl_tls_ratio = tls_count / ssl_tls_total if ssl_tls_total > 0 else 0
        ssl_flow_ratio = ssl_tls_total / non_ssl_count if non_ssl_count > 0 else 0

        return filtered_df, ssl_flow_ratio, ssl_tls_ratio, ssl_tls_total




    def calculate_duration_std_dev(df, pkt_detail_df):

        src_ip_filter = df['id.orig_h'].iloc[0]
        dest_ip_filter = df["id.resp_h"].iloc[0]
        src_port_filter = df['id.orig_p'].iloc[0]
        dest_port_filter = df['id.resp_p'].iloc[0]
        proto_filter = df['proto'].iloc[0]
        proto_filter=str(proto_filter).upper()
        # print(src_ip_filter)
        # print(dest_ip_filter)
        # print(src_port_filter)
        # print(dest_port_filter)
        # print(proto_filter)


        # SSL flow ratio
        # SSL-TLS ratio
        # SNI-SSL ratio
        # SNI as IP


        df_packet, ssl_flow_ratio, ssl_tls_ratio, ssl_tls_total= extract_packet_durations(
            pkt_detail_df,
            src_ip_filter=src_ip_filter,
            dest_ip_filter=dest_ip_filter,
            src_port_filter=src_port_filter,
            dest_port_filter=dest_port_filter,
            proto=proto_filter
        )

        # # Certificate path average
        # Check if the value is NaN before splitting
        if pd.isna(df['cert_chain_fps'].iloc[0]) or df['cert_chain_fps'].iloc[0] == '':
            num_of_certif = 0  # Handle NaN or empty case
        else:
            num_of_certif = len(df['cert_chain_fps'].iloc[0].split(','))


        # Calculate the average number of certificates safely
        Certificate_ssl_ratio = num_of_certif / ssl_tls_total if ssl_tls_total > 0 else 0
            
        
        # print(f"Number of certificates: {num_of_certif}")
        # print(f"ssl_tls_total: {ssl_tls_total}")
        # print(f"Certificate chain: {df['cert_chain_fps'].iloc[0]}")
        # print(f"Average certificate path: {avg_certif_path}")
        # print(f"no of pkt{len(df_packet)}")


        # Check if the DataFrame is empty
        if df_packet.empty:
            total_duration = df['duration'].sum()
            print(df['duration'].sum())
            print(df['orig_pkts'].sum())

            if df['orig_pkts'].sum() != 0:
                avg_duration = df['duration'].sum() / (df['orig_pkts'].sum() + df['resp_pkts'].sum())
            else:
                avg_duration = df['duration'].sum()

            std_dev = 0
            percent_std_dev = 0
            periodicity = 0
            periodicity_std = 0    
            # Inbound packets correspond to packets sent by the responder (destination)
            inbound_packets = df['resp_pkts'].sum()

            # Outbound packets correspond to packets sent by the originator (source)
            outbound_packets = df['orig_pkts'].sum()

            return total_duration, avg_duration, std_dev, percent_std_dev, periodicity,periodicity_std, ssl_flow_ratio, ssl_tls_ratio, Certificate_ssl_ratio, inbound_packets, outbound_packets
        else:
            # Calculate the total duration by summing up all packet intervals
            total_duration = df_packet['pkt_duration'].sum()
            avg_duration= total_duration/(len(df_packet))
            # print("avg_duration",avg_duration)
            # print((df_packet['pkt_duration']))
            # print((df_packet['pkt_duration']-avg_duration)**2)
            variance = ((df_packet['pkt_duration'] - avg_duration) ** 2).sum() / (len(df_packet))
            std_dev = np.sqrt(variance)
            upper_limit = avg_duration + std_dev
            lower_limit = avg_duration - std_dev
            # Count the number of packets outside the upper and lower limits
            # print("upper limit",upper_limit)
            # print("lower limit",lower_limit)
            # print(df_packet['pkt_duration'])

            # Logical AND to check both conditions
            within_limits = (df_packet['pkt_duration'] > lower_limit) & (df_packet['pkt_duration'] < upper_limit)
            # print(within_limits)
            # Count the number of True values
            count_true = within_limits.sum()
            # print(count_true)
            # print(((len(df_packet)) + 1))
            # print(f"greater than lowerlimit: {df_packet['pkt_duration'] > lower_limit}  smaller than upperlimit: {df_packet['pkt_duration'] < upper_limit}")
            # print("out of limit",out_of_limit)
            percent_std_dev = count_true / (len(df_packet))
            # print("percentage standard deviation", percent_std_dev)

            # Inbound packets correspond to packets sent by the responder (destination)
            inbound_packets = df_packet['Inbound_Packet'].sum()

            # Outbound packets correspond to packets sent by the originator (source)
            outbound_packets = df_packet['Outbound_Packet'].sum()       

            # periodicity 
            if len(df_packet) < 3:
                # Not enough data points for second differences
                # print("Not enough data to calculate second differences. Periodicity set to 0.")
                periodicity = 0
                periodicity_std = 0
                df_packet["first_diff"] = None
                df_packet["abs_first_diff"] = None
                df_packet["second_diff"] = None
                df_packet["abs_second_diff"] = None
            else:
                # Step 1: Calculate the first differences (pkt_duration.diff())
                df_packet["first_diff"] = df_packet["pkt_duration"].diff().fillna(0)
                # print(df_packet['first_diff'])
                # Step 2: Take absolute values of the first differences
                df_packet["abs_first_diff"] = df_packet["first_diff"].abs()
                # print(df_packet.loc[1:,"abs_first_diff"])
                # Step 3: Calculate the second differences (diff of abs_first_diff)
                df_packet["second_diff"] = df_packet.loc[1:,"abs_first_diff"].diff().fillna(0)
                # print(df_packet['second_diff'])

                # Step 5: Take absolute values of the second differences
                df_packet["abs_second_diff"] = df_packet["second_diff"].abs()
                # print(df_packet['abs_second_diff'])
                # print(df_packet['abs_second_diff'].sum())

                # Step 6: Calculate periodicity (mean of absolute second differences)
                non_zero_second_diff = df_packet["abs_second_diff"].dropna()[df_packet["abs_second_diff"] != 0]
                # print(len(non_zero_second_diff))
                # print(non_zero_second_diff.sum())
                periodicity = (non_zero_second_diff.sum() / len(non_zero_second_diff)) if len(non_zero_second_diff) > 0 else 0
                # Convert periodicity to Decimal
                # periodicity = float(periodicity)
                # print(periodicity)
                # print(df_packet['abs_second_diff'])

                # Step 7: Calculate periodicity standard deviation
                # print(((df_packet.loc[2:,'abs_second_diff']- periodicity)**2).sum())
                pre_variance = ((df_packet.loc[2:,'abs_second_diff']- periodicity)** 2).sum() / (len(non_zero_second_diff))
                # print(len(non_zero_second_diff))
                periodicity_std = np.sqrt(pre_variance)

                # print(f"Periodicity: {periodicity}")
                # print(f"Periodicity_std: {periodicity_std}")


            return total_duration,avg_duration, std_dev, percent_std_dev, periodicity,periodicity_std, ssl_flow_ratio, ssl_tls_ratio , Certificate_ssl_ratio, inbound_packets, outbound_packets



    # Function to calculate the payload size features
    def calculate_payload_size(df):
        orig_payload_size = df['orig_bytes'].sum()
        resp_payload_size = df['resp_bytes'].sum()
        return orig_payload_size, resp_payload_size


    def calculate_self_signed_certificate_ratio(df):

        cert_chain_fps = df['cert_chain_fps'].iloc[0]
        cert_subjects = df['certificate.subject'].iloc[0]
        cert_issuers = df['certificate.issuer'].iloc[0]
        
        san_dns_counts = 0

        if pd.isna(cert_chain_fps) or pd.isna(cert_subjects) or pd.isna(cert_issuers):
            self_signed_cert_ratio = 0
            return self_signed_cert_ratio , 0 , 0 # Handle NaN values

        # Split chains into lists
        certs = cert_chain_fps.split(',')
        subjects = cert_subjects.split('|')
        issuers = cert_issuers.split('|')

        total_certificates = len(certs)
        
        san_dns = df['san.dns'].iloc[0]
        # Handle NaN or invalid values
        if pd.isna(san_dns):
            san_dns_counts = 0
        else:
            # Normalize the splitting by replacing "|" with "," and then splitting
            san_dns_list = san_dns.replace('|', ',').split(',')
            # Remove invalid entries like 'nan' or empty strings
            valid_san_dns = [dns for dns in san_dns_list if dns.strip().lower() != "nan" and dns.strip()]
            san_dns_counts = len(valid_san_dns)
        

        avg_san_dns = (san_dns_counts/ total_certificates) if total_certificates > 0 else 0
        # print(san_dns_counts)
        # print(valid_san_dns)
        # print(f"avg_san {avg_san_dns}")

        # Ensure the number of subjects and issuers align with the number of certs
        if len(subjects) != len(issuers) or len(subjects) != len(certs):
            self_signed_cert_ratio = 0
            return self_signed_cert_ratio, len(certs), avg_san_dns # Handle mismatched lengths
        
        # Compare subjects and issuers pair-by-pair
        self_signed_cert_count = sum(1 for sub, iss in zip(subjects, issuers) if sub == iss)
        # Total number of certificates


        # Avoid division by zero
        self_signed_cert_ratio = (self_signed_cert_count / total_certificates) if total_certificates > 0 else 0

        return self_signed_cert_ratio, total_certificates, avg_san_dns



    def calculate_Public_key_average(df):
        # Extract key lengths as strings and split by '|'
        Public_key = str(df['certificate.key_length'].iloc[0]).split('|')
        
        # Handle if all values are NaN or invalid
        if all(x.strip().lower() == 'nan' or x.strip() == '' for x in Public_key):
            # If all values are NaN, return 0
            return 0

        # Convert strings to integers safely, filtering invalid entries
        try:
            Public_key = [float(x) for x in Public_key if x.strip().isdigit()]
        except ValueError:
            # Handle conversion failures
            Public_key = []

        # Handle the edge case where no valid integers were found
        if len(Public_key) == 0:
            return 0

        # Calculate the average
        Public_key_average = sum(Public_key) / len(Public_key)

        # print("Keys:", Public_key)
        # print("Average:", Public_key_average)

        return Public_key_average


    def calculate_certificate_validity_metrics(df):
        """
        Calculate certificate validity metrics, including:
        - Average validity duration in days
        - Standard deviation of validity durations
        - Combined binary validity indicating if any certificate is valid during capture timestamp (`cert_ts`)
        - Average certificate age

        Parameters:
            df (pd.DataFrame): A DataFrame containing:
                - `certificate.not_valid_before`: Pipe-separated "not valid before" timestamps for certificates.
                - `certificate.not_valid_after`: Pipe-separated "not valid after" timestamps for certificates.
                - `cert_ts`: Pipe-separated capture timestamps.

        Returns:
            tuple:
                - average_validity (float): Average validity duration in days.
                - std_dev (float): Standard deviation of validity durations.
                - overall_validity (int): 1 if any certificate is valid during capture, 0 otherwise.
                - avg_cert_age (float): Average certificate age.
        """
        # Split the certificate validity dates and capture timestamps into lists
        not_valid_before = str(df['certificate.not_valid_before'].iloc[0]).split('|')
        not_valid_after = str(df['certificate.not_valid_after'].iloc[0]).split('|')
        cert_ts = str(df['cert_ts'].iloc[0]).split('|')

        # Handle edge cases: Missing or mismatched entries
        if len(not_valid_before) != len(not_valid_after) or len(not_valid_before) != len(cert_ts):
            return 0, 0, 0, 0  # Invalid data scenario

        # Initialize variables for validity calculations
        validity_durations = []
        overall_validity = 0
        certificate_ages = []

        # print(not_valid_after)
        # print(not_valid_before)
        # print(cert_ts)
        # Process each certificate
        for before, after, ts in zip(not_valid_before, not_valid_after, cert_ts):
            try:
                # Convert strings to integers or floats
                before_int = float(before)
                after_int = float(after)
                ts_float = float(ts)
                # print(before_int)
                # print(after_int)
                # print(ts_float)

                # Calculate validity duration in days
                duration_seconds = after_int - before_int
                if duration_seconds > 0:
                    duration_days = duration_seconds / (24 * 3600)  # Convert seconds to days
                    validity_durations.append(duration_days)

                # Check if the capture timestamp falls within the validity period
                if before_int <= ts_float <= after_int:
                    overall_validity = 1  # Logical OR to determine overall validity

                # Calculate certificate age
                first_time_period = ts_float - before_int
                second_time_period = after_int - before_int
                # print(f"first period {first_time_period}")
                # print(f"second period {second_time_period}")
                if second_time_period > 0 and first_time_period >= 0:
                    certificate_age = first_time_period / second_time_period
                    certificate_ages.append(certificate_age)
                else:
                    certificate_ages.append(0)

                # print("running")
            except ValueError:
                # Skip invalid or unparsable values
                # print("skipping")
                continue

        # Handle edge case: No valid durations
        if len(validity_durations) == 0:
            return 0, 0, overall_validity, 0

        # Compute average and standard deviation of validity durations
        average_validity = np.mean(validity_durations)
        std_dev = np.std(validity_durations)

        # print(certificate_ages)
        # Compute average certificate age
        avg_cert_age = np.mean(certificate_ages) if certificate_ages else 0

        return average_validity, std_dev, overall_validity, avg_cert_age


    def calculate_CN_in_SAN_DNS(df):
        CN = df['certificate.subject'].iloc[0]

        # Ensure it's a valid string, or return 0 if it's NaN or invalid
        if pd.isna(CN) or not isinstance(CN, str):
            # print("Certificate subject is invalid or NaN.")
            return 0

        # print(f"Certificate Subject (CN String): {CN}")

        san_dns = df['san.dns'].iloc[0]
        # Handle NaN or invalid values
        if pd.isna(san_dns):
            valid_san_dns = []
        else:
            # Normalize the splitting by replacing "|" with "," and then splitting
            san_dns_list = san_dns.replace('|', ',').split(',')
            # Remove invalid entries like 'nan' or empty strings
            valid_san_dns = [dns for dns in san_dns_list if dns.strip().lower() != "nan" and dns.strip()]
        
        cn_matches = re.findall(r'CN=([^,|]+)', CN)
        # print(f"Extracted CN values: {cn_matches}")

        # Compare extracted CNs with the SAN DNS list
        if any(cn in valid_san_dns for cn in cn_matches):
            # print("At least one CN found in SAN DNS.")
            return 1
        else:
            # print("No CN found in SAN DNS.")
            return 0
        



    #Function to extract features for each flow
    def extract_features(df):
        # 2,3,4. Standard Deviation of Flow Durations
        duration, avg_duration, duration_std_dev, percent_std_dev, periodicity, periodicity_std, ssl_flow_ratio, ssl_tls_ratio, Certificate_ssl_ratio, inbound_packets, outbound_packets= calculate_duration_std_dev(df,pkt_detail_df)

        # # 5. Originator Payload Size
        orig_payload_size, resp_payload_size = calculate_payload_size(df)

        # 6. Responder Payload Size
        # This is the resp_payload_size, calculated already in the previous step

        # 7. Ratio of Responder to Originator Payload Size
        payload_ratio = resp_payload_size / orig_payload_size if orig_payload_size != 0 else 0


        # self signed certificate ratio
        self_signed_cert_ratio, total_certificates, avg_san_dns  = calculate_self_signed_certificate_ratio(df)

        # public key average
        Public_key_average = calculate_Public_key_average(df)

        # certificate validity days average
        average_validity, Std_dev_cert_validity, overall_validity, avg_cert_age = calculate_certificate_validity_metrics(df)

        # # Sni in san.dns
        # SNI_in_SAN_dns = calculate_SNI_in_SAN_dns(df)

        # CN in san.dns
        CN_in_SAN_DNS = calculate_CN_in_SAN_DNS(df)

        # Return the extracted features as a dictionary
        features = {
            'duration': duration,
            'avg_duration': avg_duration,
            'duration_std_dev': duration_std_dev,
            'percent_std_dev': percent_std_dev,
            'orig_payload_size': orig_payload_size,
            'resp_payload_size': resp_payload_size,
            'payload_ratio': payload_ratio,
            'inbound_packets': inbound_packets,
            'outbound_packets': outbound_packets,
            'avg_periodicity': periodicity,
            'periodicity_std': periodicity_std,
            'ssl_flow_ratio' : ssl_flow_ratio,
            'ssl_tls_ratio': ssl_tls_ratio,
            'self_signed_cert_ratio' : self_signed_cert_ratio,
            'Public_key_average' : Public_key_average,
            'average_validity' : average_validity,
            'Std_dev_cert_validity' : Std_dev_cert_validity,
            'Cert_val_during_capture' : overall_validity,
            'avg_cert_age' : avg_cert_age,
            'total_certificates' : total_certificates,
            'avg_san_dns' : avg_san_dns,
            'Certificate_ssl_ratio' : Certificate_ssl_ratio,
            # 'SNI_in_SAN_dns' : SNI_in_SAN_dns,
            'CN_in_SAN_DNS' : CN_in_SAN_DNS
        }
        
        return features


    # Main function to process the CSV and extract features for all flows
    def process_flows(file_path):
        # Load the CSV into a DataFrame
        df = pd.read_csv(file_path)
        
        # Group the data by flow (using 'uid' as the unique identifier for a flow)
        flows = df.groupby('uid')

        # Initialize an empty list to store the features for each flow
        flow_features = []

        # Loop through each group (flow) and extract features
        for idx, (uid, group) in enumerate(flows, 1):
            # print(f"Flow ID: {uid}, Rows in group: {len(group)}")
            features = extract_features(group)
            source_ip = group['id.orig_h'].iloc[0]
            dest_ip = group['id.resp_h'].iloc[0]
            source_port = group['id.orig_p'].iloc[0]
            dest_port = group['id.resp_p'].iloc[0]
            proto = group['proto'].iloc[0]

            # Add the unique flow number
            features['flow_number'] = idx

            # Append the features along with the source and destination IP and port
            features['source_ip'] = source_ip
            features['dest_ip'] = dest_ip
            features['source_port'] = source_port
            features['dest_port'] = dest_port
            features['proto'] = proto

            flow_features.append(features)

        # Convert the list of features into a DataFrame
        features_df = pd.DataFrame(flow_features)


        # Reorder the columns as per your requirement: first five features should be source IP, dest IP, ports, and protocol
        columns_order = ['flow_number',         'source_ip',            'dest_ip',                  'source_port',
                        'dest_port',           'proto',                'duration',                 'avg_duration',
                        'duration_std_dev',    'percent_std_dev',      'orig_payload_size',        'resp_payload_size',
                        'payload_ratio',       'inbound_packets',      'outbound_packets',         'avg_periodicity',
                        'periodicity_std',     'ssl_flow_ratio',       'ssl_tls_ratio',            'self_signed_cert_ratio',
                        'Public_key_average',  'average_validity',    'Std_dev_cert_validity','Cert_val_during_capture',
                        'avg_cert_age',        'total_certificates',  'avg_san_dns',          'Certificate_ssl_ratio',
                        'CN_in_SAN_DNS']
        

        features_df = features_df[columns_order]
        
        return features_df


    # Function to save the extracted features to a CSV file
    def save_features_to_csv(features_df, output_file):
        features_df.to_csv(output_file, index=False)
        print(f"Features saved to {output_file}")


    # Path to your ssl.csv and x509.csv files
    output_filename = f"{folder_name}.csv"
    file_path = os.path.join(folder_path, output_filename)  # Replace with your actual file path
    features_df = process_flows(file_path)

    # Save the features to a CSV file
    output_file = os.path.join(output_file_p, output_filename)  # Specify the output file name
    save_features_to_csv(features_df, output_file)


