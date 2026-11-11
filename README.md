# Network Intrusion Detection System Using Machine Learning

A machine learning project to detect network attacks and intrusions using the CICIDS2017 dataset.

## Project Overview
This project classifies network traffic flows into normal traffic (BENIGN) and 11 different types of cyber attacks using supervised machine learning algorithms.

### Attacks Detected
- BENIGN (Normal traffic)
- DoS Hulk
- PortScan
- DDoS
- DoS GoldenEye
- FTP-Patator
- SSH-Patator
- DoS slowloris
- DoS Slowhttptest
- Bot
- Web Attack
- Infiltration

## Project Structure
- notebooks/: Contains the step-by-step Jupyter notebook for data preprocessing, EDA, model training, and evaluation.
- models/: Contains the saved model pipeline file (random_forest_nids_model.joblib).
- data/: Contains sample test flows for testing predictions.
- app/: Streamlit web application for interactive intrusion detection.

## Models Evaluated
- Decision Tree Classifier
- Random Forest Classifier (Selected Model - 99.27% accuracy)

## How to Run the Streamlit Application
1. Install requirements:
   pip install -r requirements.txt
2. Run the application:
   streamlit run app/app.py
