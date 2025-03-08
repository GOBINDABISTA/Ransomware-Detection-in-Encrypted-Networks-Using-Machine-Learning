import pandas as pd
import numpy as np
import os
import shutil


def process_folder(folder_path, folder_name):
    print("process_folder")
    """Check for conn.log, ssl.log, and x509.log in the folder and log their presence."""
    print(f"Processing folder: {folder_path}")

    conn_csv = os.path.join(folder_path, "conn.csv")
    ssl_csv = os.path.join(folder_path, "ssl.csv")
    x509_csv = os.path.join(folder_path, "x509.csv")

    # Dynamically create the output CSV path
    output_filename = f"{folder_name}.csv"
    output_path = os.path.join(folder_path, output_filename)
    print(f"print output path{output_path}")
    flow_maker(x509_csv, ssl_csv, conn_csv, output_path)


def move_to_completed(folder_name, base_path, completed_path):
    """Move processed folder to completed directory."""
    src = os.path.join(base_path, folder_name)
    dest = os.path.join(completed_path, folder_name)
    shutil.move(src, dest)
    print(f"Moved {folder_name} to completed.")


def flow_maker(x509_csv, ssl_csv, conn_csv, output_path):

    # Load the CSV files safely with existence checks
    conn_df = pd.read_csv(conn_csv) if os.path.isfile(conn_csv) else pd.DataFrame()
    ssl_df = pd.read_csv(ssl_csv) if os.path.isfile(ssl_csv) else pd.DataFrame()
    x509_df = pd.read_csv(x509_csv) if os.path.isfile(x509_csv) else pd.DataFrame()

    # Debugging: Log if x509_df loaded successfully
    if x509_df.empty:
        print("No X509 data found in 'x509.csv'")
    else:
        print(f"Loaded X509 data with {len(x509_df)} entries.")
        
    # Set X509 Data to dictionary for easier lookup by fingerprint
    x509_dict = x509_df.set_index('fingerprint').to_dict(orient='index') if not x509_df.empty else {}

    # Debugging: Log fingerprints in the dictionary
    if x509_dict:
        print(f"Fingerprint keys loaded: {list(x509_dict.keys())}")
    else:
        print("X509 dictionary is empty.")

    # Define SSL fields
    ssl_features_to_add = [
        'version', 'cipher', 'curve', 'server_name', 'resumed', 'last_alert',
        'next_protocol', 'established', 'ssl_history', 'cert_chain_fps',
        'client_cert_chain_fps', 'sni_matches_cert'
    ]

    # Extracted X509 fields
    x509_features_to_extract = [
        'certificate.version', 'certificate.serial', 'certificate.subject',
        'certificate.issuer', 'certificate.not_valid_before', 'certificate.not_valid_after',
        'certificate.key_alg', 'certificate.sig_alg', 'certificate.key_type',
        'certificate.key_length', 'certificate.exponent', 'certificate.curve',
        'san.dns', 'san.uri', 'san.email', 'san.ip',
        'basic_constraints.ca', 'basic_constraints.path_len',
        'host_cert', 'client_cert', 'cert_ts'
    ]

    # Connection fields to expect
    conn_features_to_add = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
        'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'
    ]

    # Final desired feature order (SSL headers first, followed by X509 fields, followed by connection fields)
    final_headers = ssl_features_to_add + x509_features_to_extract + conn_features_to_add


    # Initialize dictionary for data processing
    flow_dict = {}


    # Process SSL Data only if ssl_df is not empty
    if not ssl_df.empty:
        for index, ssl_row in ssl_df.iterrows():
            # Define the key as the tuple of flow features
            flow_key = (ssl_row['id.orig_h'], ssl_row['id.resp_h'], ssl_row['id.orig_p'], ssl_row['id.resp_p'])

            # Map SSL fields safely
            flow_dict[flow_key] = {
                'version': ssl_row.get('version', np.nan),
                'cipher': ssl_row.get('cipher', np.nan),
                'curve': ssl_row.get('curve', np.nan),
                'server_name': ssl_row.get('server_name', np.nan),
                'resumed': ssl_row.get('resumed', np.nan),
                'last_alert': ssl_row.get('last_alert', np.nan),
                'next_protocol': ssl_row.get('next_protocol', np.nan),
                'established': ssl_row.get('established', np.nan),
                'ssl_history': ssl_row.get('ssl_history', np.nan),
                'cert_chain_fps': ssl_row.get('cert_chain_fps', np.nan),
                'client_cert_chain_fps': ssl_row.get('client_cert_chain_fps', np.nan),
                'sni_matches_cert': ssl_row.get('sni_matches_cert', np.nan)
            }

            # Map X509 fields if cert_chain_fps exists
            if pd.notna(ssl_row.get('cert_chain_fps')) and ssl_row.get('cert_chain_fps') != '-':
                cert_features = []
                for fingerprint in ssl_row['cert_chain_fps'].split(','):
                    if fingerprint in x509_dict:
                        cert_data = x509_dict[fingerprint]
                        cert_features.append({
                            'certificate.version': str(cert_data.get('certificate.version', np.nan)),
                            'certificate.serial': str(cert_data.get('certificate.serial', np.nan)),
                            'certificate.subject': str(cert_data.get('certificate.subject', np.nan)),
                            'certificate.issuer': str(cert_data.get('certificate.issuer', np.nan)),
                            'certificate.not_valid_before': str(cert_data.get('certificate.not_valid_before', np.nan)),
                            'certificate.not_valid_after': str(cert_data.get('certificate.not_valid_after', np.nan)),
                            'certificate.key_alg': str(cert_data.get('certificate.key_alg', np.nan)),
                            'certificate.sig_alg': str(cert_data.get('certificate.sig_alg', np.nan)),
                            'certificate.key_type': str(cert_data.get('certificate.key_type', np.nan)),
                            'certificate.key_length': str(cert_data.get('certificate.key_length', np.nan)),
                            'certificate.exponent': str(cert_data.get('certificate.exponent', np.nan)),
                            'certificate.curve': str(cert_data.get('certificate.curve', np.nan)),
                            'san.dns': str(cert_data.get('san.dns', np.nan)),
                            'san.uri': str(cert_data.get('san.uri', np.nan)),
                            'san.email': str(cert_data.get('san.email', np.nan)),
                            'san.ip': str(cert_data.get('san.ip', np.nan)),
                            'basic_constraints.ca': str(cert_data.get('basic_constraints.ca', np.nan)),
                            'basic_constraints.path_len': str(cert_data.get('basic_constraints.path_len', np.nan)),
                            'host_cert': str(cert_data.get('host_cert', np.nan)),
                            'client_cert': str(cert_data.get('client_cert', np.nan)),
                            'cert_ts': str(cert_data.get('ts', np.nan))  # Extract cert_ts safely
                        })

                # Aggregate extracted X509 features
                aggregated_features = {
                    feature: '|'.join([cf[feature] for cf in cert_features]) if cert_features else np.nan
                    for feature in x509_features_to_extract
                }

                # Update dictionary with extracted features
                flow_dict[flow_key].update(aggregated_features)


    # Process connection data
    for index, conn_row in conn_df.iterrows():
        flow_key = (conn_row['id.orig_h'], conn_row['id.resp_h'], conn_row['id.orig_p'], conn_row['id.resp_p'])
        if flow_key not in flow_dict:
            # Ensure all fields are initialized
            flow_dict[flow_key] = {header: np.nan for header in final_headers}
        for col in conn_features_to_add:
            flow_dict[flow_key][col] = conn_row[col]

    # Convert to DataFrame
    final_df = pd.DataFrame(list(flow_dict.values()))
    final_df = final_df.reindex(columns=final_headers, fill_value=np.nan)

    # Save to CSV
    final_df.to_csv(output_path, index=False)

    print(f"Dataset Flow_features process successfully to {output_path}.")