# Ransomware Detection in Encrypted Networks Using Machine Learning

## Overview
This project focuses on detecting ransomware in encrypted network traffic using **machine learning** techniques, ensuring privacy by avoiding decryption. It integrates **Cuckoo Sandbox** for dynamic malware analysis, extracts statistical traffic features, and applies ML models for accurate classification.

## Features
- **Privacy-Preserving Detection** – Identifies ransomware without decrypting network traffic.
- **Cuckoo Sandbox Integration** – Analyzes ransomware behavior dynamically.
- **Feature Extraction** – Uses network flow-based statistical features.
- **Machine Learning Models** – Implements **Random Forest, XGBoost, SVM**, and others.
- **Real-Time Detection** – Utilizes **Zeek, Wireshark, and Flask** for live monitoring.

## Technologies Used
- **Python, Scikit-Learn, XGBoost** – Machine learning model training.
- **Zeek (Bro), Wireshark** – Network traffic analysis.
- **Cuckoo Sandbox** – Malware analysis.
- **Flask** – Web-based real-time detection system.

## Installation
```bash
# Clone the repository
git clone https://github.com/GOBINDABISTA/Ransomware-Detection-in-Encrypted-Networks-Using-Machine-Learning.git
cd Ransomware-Detection-in-Encrypted-Networks-Using-Machine-Learning

# Install dependencies
pip install -r requirements.txt
```

## Usage
```bash
# Start Zeek for network traffic monitoring
zeek -r <pcap_file>

# Run the machine learning model for ransomware detection
python Detection.py
```

## Dataset
- The model is trained on labeled network traffic datasets containing ransomware and benign samples.

## Future Enhancements
- Implement **Deep Learning** for improved accuracy.
- Optimize real-time detection speed.

## Author
- **Gobinda Bista**  
  [GitHub Profile](https://github.com/GOBINDABISTA)

## License
This project is licensed under the **MIT License**.
