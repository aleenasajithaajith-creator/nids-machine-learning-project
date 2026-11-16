import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import io
import datetime
import plotly.graph_objects as go
import plotly.express as px
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Page Configuration
st.set_page_config(
    page_title="NETGUARD AI - Network Intrusion Detection System",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark Cybersecurity SOC Theme Styles
st.markdown("""
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #0B1120;
        color: #F8FAFC;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1E293B;
    }
    section[data-testid="stSidebar"] .stMarkdown {
        color: #94A3B8;
    }
    
    /* Custom Header Card */
    .soc-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        border: 1px solid #334155;
        border-left: 5px solid #3B82F6;
        padding: 22px 28px;
        border-radius: 8px;
        margin-bottom: 24px;
    }
    .soc-header h1 {
        font-size: 24px;
        font-weight: 700;
        color: #F8FAFC;
        margin: 0 0 6px 0;
        letter-spacing: -0.5px;
    }
    .soc-header p {
        font-size: 13px;
        color: #94A3B8;
        margin: 0;
    }
    .soc-header-badges {
        display: flex;
        gap: 10px;
        margin-top: 12px;
        flex-wrap: wrap;
    }
    .soc-badge {
        font-size: 11px;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 4px;
        background-color: rgba(59, 130, 246, 0.15);
        color: #60A5FA;
        border: 1px solid rgba(59, 130, 246, 0.3);
    }
    
    /* KPI Metric Cards */
    .soc-metric {
        background-color: #182235;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 12px;
    }
    .soc-metric-total {
        border-left: 4px solid #3B82F6;
    }
    .soc-metric-safe {
        border-left: 4px solid #22C55E;
    }
    .soc-metric-threat {
        border-left: 4px solid #EF4444;
    }
    .soc-metric-rate {
        border-left: 4px solid #F59E0B;
    }
    .soc-metric-label {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #94A3B8;
        margin-bottom: 4px;
    }
    .soc-metric-value {
        font-size: 26px;
        font-weight: 800;
        color: #F8FAFC;
    }
    .soc-metric-sub {
        font-size: 11px;
        color: #64748B;
        margin-top: 4px;
    }
    
    /* Secondary Stat Box */
    .stat-pill {
        background-color: #182235;
        border: 1px solid #1E293B;
        border-radius: 6px;
        padding: 10px 14px;
        text-align: center;
    }
    .stat-pill-label {
        font-size: 10px;
        text-transform: uppercase;
        color: #64748B;
        font-weight: 600;
    }
    .stat-pill-val {
        font-size: 15px;
        font-weight: 700;
        color: #F8FAFC;
        margin-top: 2px;
    }
    
    /* Content Card */
    .soc-card {
        background-color: #182235;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 20px;
    }
    .soc-card-title {
        font-size: 16px;
        font-weight: 700;
        color: #F8FAFC;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid #1E293B;
    }
    
    /* Threat Spotlight Cards */
    .spotlight-card {
        background-color: #182235;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .spotlight-threat {
        border-left: 4px solid #EF4444;
    }
    .spotlight-safe {
        border-left: 4px solid #22C55E;
    }
</style>
""", unsafe_allow_html=True)

# Severity and Knowledge Base Configuration
SEVERITY_CONFIG = {
    'BENIGN': {'level': 'Low', 'color': '#22C55E', 'desc': 'Legitimate operational traffic without malicious signatures.'},
    'PortScan': {'level': 'Medium', 'color': '#F59E0B', 'desc': 'Reconnaissance probe scanning sequential ports to map active services.'},
    'Bot': {'level': 'Medium', 'color': '#F59E0B', 'desc': 'Infected endpoint communicating with an external Command-and-Control (C2) server.'},
    'DoS Hulk': {'level': 'High', 'color': '#EA580C', 'desc': 'High-volume HTTP flood generating unique request obfuscations to exhaust web server pools.'},
    'DoS Slowloris': {'level': 'High', 'color': '#EA580C', 'desc': 'Low-and-slow HTTP attack sending incomplete headers to hold server sockets open indefinitely.'},
    'DoS GoldenEye': {'level': 'High', 'color': '#EA580C', 'desc': 'HTTP Keep-Alive exhaustion attack designed to consume max server connection pools.'},
    'DoS Slowhttptest': {'level': 'High', 'color': '#EA580C', 'desc': 'Slow-read HTTP POST exhaustion attack starving thread execution queues.'},
    'FTP-Patator': {'level': 'High', 'color': '#EA580C', 'desc': 'Brute-force credential dictionary attack targeting File Transfer Protocol (Port 21).'},
    'SSH-Patator': {'level': 'High', 'color': '#EA580C', 'desc': 'Automated SSH authentication attack attempting password exhaustion (Port 22).'},
    'Web Attack': {'level': 'High', 'color': '#EA580C', 'desc': 'Web application vulnerability exploitation including SQLi, XSS, and brute force.'},
    'DDoS': {'level': 'Critical', 'color': '#EF4444', 'desc': 'Large-scale distributed volumetric flood targeting network bandwidth and gateway buffers.'},
    'Infiltration': {'level': 'Critical', 'color': '#EF4444', 'desc': 'Internal network reconnaissance and privilege escalation following gateway compromise.'}
}

def get_severity(cls_name):
    for k, v in SEVERITY_CONFIG.items():
        if k.lower() == str(cls_name).lower():
            return v['level']
    return 'Low' if str(cls_name).upper() == 'BENIGN' else 'Medium'

# Load Model
@st.cache_resource
def load_nids_model():
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "models", "random_forest_nids_model.joblib"),
        r"D:\NIDS_ML_Project\models\random_forest_nids_model.joblib"
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                data = joblib.load(p)
                return data, None
            except Exception as e:
                return None, f"Model load error: {e}"
    return None, "Model file not found."

model_bundle, model_load_err = load_nids_model()
rf_model = model_bundle.get("model") if model_bundle else None
scaler = model_bundle.get("scaler") if model_bundle else None
label_encoder = model_bundle.get("label_encoder") if model_bundle else None
feature_names = model_bundle.get("feature_names") if model_bundle else None

# Sidebar Navigation (Clean, Professional, Minimal)
st.sidebar.markdown("""
<div style="padding: 10px 0 16px 0; border-bottom: 1px solid #1E293B; margin-bottom: 16px;">
    <div style="font-size: 20px; font-weight: 800; color: #3B82F6; letter-spacing: 1px;">NETGUARD AI</div>
    <div style="font-size: 11px; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px;">SOC Threat Intelligence Platform</div>
</div>
""", unsafe_allow_html=True)

nav_options = [
    "Dashboard",
    "Traffic Analysis",
    "Prediction Results",
    "Attack Intelligence",
    "Model Performance",
    "Reports",
    "About Project"
]

selected_page = st.sidebar.radio("Navigation Menu", nav_options, index=0)

# Bottom Model Status in Sidebar
st.sidebar.markdown("---")
if model_bundle:
    st.sidebar.markdown("""
    <div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 6px;">
        <span style="height: 8px; width: 8px; background-color: #22C55E; border-radius: 50%; display: inline-block;"></span>
        <span style="font-size: 12px; font-weight: 600; color: #4ADE80;">Model Loaded (Random Forest)</span>
    </div>
    """, unsafe_allow_html=True)
else:
    st.sidebar.markdown("""
    <div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px;">
        <span style="height: 8px; width: 8px; background-color: #EF4444; border-radius: 50%; display: inline-block;"></span>
        <span style="font-size: 12px; font-weight: 600; color: #F87171;">Model Not Loaded</span>
    </div>
    """, unsafe_allow_html=True)

if 'results_df' in st.session_state and st.session_state['results_df'] is not None:
    ds_name = st.session_state.get('dataset_name', 'Loaded Dataset')
    flow_cnt = len(st.session_state['results_df'])
    st.sidebar.markdown(f"""
    <div style="margin-top: 10px; padding: 8px 12px; background: #182235; border: 1px solid #1E293B; border-radius: 6px;">
        <div style="font-size: 10px; color: #94A3B8; text-transform: uppercase;">Active Dataset</div>
        <div style="font-size: 12px; font-weight: 600; color: #F8FAFC; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{ds_name}</div>
        <div style="font-size: 11px; color: #3B82F6;">{flow_cnt:,} flows analyzed</div>
    </div>
    """, unsafe_allow_html=True)

# Top Header Banner
st.markdown("""
<div class="soc-header">
    <h1>NETWORK INTRUSION DETECTION SYSTEM</h1>
    <p>AI-powered Network Traffic Classification and Threat Detection</p>
    <div class="soc-header-badges">
        <span class="soc-badge">Platform: NETGUARD AI</span>
        <span class="soc-badge">Algorithm: Random Forest Classifier</span>
        <span class="soc-badge">Benchmark: CICIDS2017</span>
        <span class="soc-badge">Monitored Features: 70 Statistical Parameters</span>
        <span class="soc-badge">Multiclass Scope: 12 Traffic Categories</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Helper Function: Process Dataset through ML Pipeline
def run_ml_pipeline(input_df, filename):
    clean_df = input_df.copy()
    clean_df.columns = clean_df.columns.str.strip()
    
    # Identify Ground Truth if present (safely separated from feature matrix)
    ground_truth_col = None
    for cand in ["Ground_Truth_Label", "Label", "label", "Class"]:
        if cand in clean_df.columns:
            ground_truth_col = cand
            break
            
    # Verify 70 features
    missing_feats = [f for f in feature_names if f not in clean_df.columns]
    if missing_feats:
        st.warning(f"Note: {len(missing_feats)} features were missing in uploaded data. Clamped with default zeros.")
        for f in missing_feats:
            clean_df[f] = 0.0
            
    X = clean_df[feature_names].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    
    # Scale and Predict
    X_scaled = scaler.transform(X)
    numeric_preds = rf_model.predict(X_scaled)
    predicted_classes = label_encoder.inverse_transform(numeric_preds)
    
    # Confidence Probabilities
    try:
        probs = rf_model.predict_proba(X_scaled)
        confidences = np.max(probs, axis=1) * 100
    except Exception:
        confidences = np.ones(len(numeric_preds)) * 100.0
        
    severities = [get_severity(c) for c in predicted_classes]
    traffic_types = ["Normal" if p.upper() == "BENIGN" else "Malicious" for p in predicted_classes]
    
    # Assemble comprehensive results dataframe
    results = clean_df.copy()
    results.insert(0, "Flow_ID", [f"FL-{i+1:04d}" for i in range(len(results))])
    results["Predicted_Class"] = predicted_classes
    results["Confidence"] = np.round(confidences, 2)
    results["Severity"] = severities
    results["Traffic_Type"] = traffic_types
    
    if ground_truth_col:
        actuals = clean_df[ground_truth_col].astype(str).str.strip().values
        results["Actual_Class"] = actuals
        results["Validation_Status"] = ["Correct" if p.lower() == a.lower() else "Incorrect" for p, a in zip(predicted_classes, actuals)]
        
    # Update Session State
    st.session_state["results_df"] = results
    st.session_state["dataset_name"] = filename
    st.session_state["analysis_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["has_ground_truth"] = (ground_truth_col is not None)
    return results


# ==========================================
# PAGE 1: DASHBOARD
# ==========================================
if selected_page == "Dashboard":
    if "results_df" not in st.session_state or st.session_state["results_df"] is None:
        st.markdown("""
        <div class="soc-card" style="text-align: center; padding: 40px;">
            <div style="font-size: 18px; font-weight: 700; color: #F8FAFC; margin-bottom: 8px;">Awaiting Network Traffic Data</div>
            <div style="font-size: 13px; color: #94A3B8; max-width: 600px; margin: 0 auto 20px auto;">
                No active traffic capture has been analyzed yet in this session. Navigate to <strong>Traffic Analysis</strong> to upload a network CSV capture or load one of the authentic benchmark datasets.
            </div>
        </div>
        """, unsafe_allow_html=True)
        col_act1, col_act2, col_act3 = st.columns([1, 1, 1])
        with col_act2:
            if st.button("Proceed to Traffic Analysis Page", use_container_width=True):
                st.session_state["nav_target"] = "Traffic Analysis"
                st.rerun()
    else:
        df_res = st.session_state["results_df"]
        total_cnt = len(df_res)
        normal_cnt = int(np.sum(df_res["Traffic_Type"] == "Normal"))
        threat_cnt = int(total_cnt - normal_cnt)
        threat_rate = (threat_cnt / total_cnt * 100) if total_cnt > 0 else 0.0
        
        # 4 Primary KPI Cards
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""
            <div class="soc-metric soc-metric-total">
                <div class="soc-metric-label">Total Flows Analyzed</div>
                <div class="soc-metric-value">{total_cnt:,}</div>
                <div class="soc-metric-sub">Dataset: {st.session_state.get('dataset_name', 'Active')}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            normal_pct = (normal_cnt / total_cnt * 100) if total_cnt > 0 else 0
            st.markdown(f"""
            <div class="soc-metric soc-metric-safe">
                <div class="soc-metric-label">Normal Traffic</div>
                <div class="soc-metric-value">{normal_cnt:,}</div>
                <div class="soc-metric-sub">{normal_pct:.1f}% legitimate flows</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="soc-metric soc-metric-threat">
                <div class="soc-metric-label">Malicious Threats</div>
                <div class="soc-metric-value">{threat_cnt:,}</div>
                <div class="soc-metric-sub">Identified cyber intrusions</div>
            </div>
            """, unsafe_allow_html=True)
        with col4:
            st.markdown(f"""
            <div class="soc-metric soc-metric-rate">
                <div class="soc-metric-label">Threat Detection Rate</div>
                <div class="soc-metric-value">{threat_rate:.1f}%</div>
                <div class="soc-metric-sub">Overall risk proportion</div>
            </div>
            """, unsafe_allow_html=True)
            
        # Secondary Statistics Bar
        threats_only = df_res[df_res["Traffic_Type"] == "Malicious"]
        top_attack = threats_only["Predicted_Class"].mode()[0] if not threats_only.empty else "None"
        unique_attacks = threats_only["Predicted_Class"].nunique()
        high_crit_cnt = int(np.sum(df_res["Severity"].isin(["High", "Critical"])))
        
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.markdown(f"""
            <div class="stat-pill">
                <div class="stat-pill-label">Most Frequent Attack</div>
                <div class="stat-pill-val">{top_attack}</div>
            </div>
            """, unsafe_allow_html=True)
        with p2:
            st.markdown(f"""
            <div class="stat-pill">
                <div class="stat-pill-label">Unique Attack Categories</div>
                <div class="stat-pill-val">{unique_attacks}</div>
            </div>
            """, unsafe_allow_html=True)
        with p3:
            st.markdown(f"""
            <div class="stat-pill">
                <div class="stat-pill-label">High / Critical Threats</div>
                <div class="stat-pill-val" style="color: #EF4444;">{high_crit_cnt}</div>
            </div>
            """, unsafe_allow_html=True)
        with p4:
            st.markdown(f"""
            <div class="stat-pill">
                <div class="stat-pill-label">Analysis Status</div>
                <div class="stat-pill-val" style="color: #22C55E;">Verified Active</div>
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Dashboard Visualizations
        ch_col1, ch_col2 = st.columns([1, 1])
        
        with ch_col1:
            st.markdown("<div class='soc-card-title'>Normal vs Malicious Traffic Distribution</div>", unsafe_allow_html=True)
            donut_fig = go.Figure(data=[go.Pie(
                labels=['Normal Traffic', 'Malicious Traffic'],
                values=[normal_cnt, threat_cnt],
                hole=0.62,
                marker=dict(colors=['#22C55E', '#EF4444'], line=dict(color='#0B1120', width=2)),
                textinfo='label+percent',
                textfont=dict(color='#F8FAFC')
            )])
            donut_fig.update_layout(
                paper_bgcolor='#182235',
                plot_bgcolor='#182235',
                margin=dict(l=20, r=20, t=20, b=20),
                height=280,
                showlegend=False,
                annotations=[dict(text=f"{threat_rate:.1f}%<br>Threat", x=0.5, y=0.5, font_size=16, font_color="#EF4444", showarrow=False)]
            )
            st.plotly_chart(donut_fig, use_container_width=True)
            
        with ch_col2:
            st.markdown("<div class='soc-card-title'>Attack Category Breakdown</div>", unsafe_allow_html=True)
            cat_counts = df_res["Predicted_Class"].value_counts().reset_index()
            cat_counts.columns = ["Category", "Count"]
            bar_fig = px.bar(
                cat_counts,
                x="Count",
                y="Category",
                orientation='h',
                color="Category",
                color_discrete_map={'BENIGN': '#22C55E'},
                text="Count"
            )
            bar_fig.update_layout(
                paper_bgcolor='#182235',
                plot_bgcolor='#182235',
                font=dict(color='#F8FAFC'),
                margin=dict(l=20, r=20, t=20, b=20),
                height=280,
                showlegend=False,
                xaxis=dict(showgrid=True, gridcolor='#1E293B', title="Flows"),
                yaxis=dict(title=None, autorange="reversed")
            )
            bar_fig.update_traces(textposition='outside')
            st.plotly_chart(bar_fig, use_container_width=True)
            
        # Recent Prediction Activity
        st.markdown("<div class='soc-card-title'>Recent Traffic Inspection Records</div>", unsafe_allow_html=True)
        disp_cols = ["Flow_ID", "Predicted_Class", "Confidence", "Severity", "Traffic_Type"]
        if "Actual_Class" in df_res.columns:
            disp_cols += ["Actual_Class", "Validation_Status"]
        if "Destination Port" in df_res.columns:
            disp_cols.append("Destination Port")
        if "Flow Duration" in df_res.columns:
            disp_cols.append("Flow Duration")
            
        st.dataframe(df_res[disp_cols].head(8), use_container_width=True, hide_index=True)


# ==========================================
# PAGE 2: TRAFFIC ANALYSIS
# ==========================================
elif selected_page == "Traffic Analysis":
    st.markdown('<div class="soc-card-title">1. Dataset Selection & Traffic Ingestion</div>', unsafe_allow_html=True)
    
    tab_upload, tab_sample = st.tabs(["Upload Custom CSV", "Load Benchmark Sample Dataset"])
    
    selected_df = None
    input_source_name = ""
    
    with tab_upload:
        uploaded_file = st.file_uploader(
            "Select or drop a network flow CSV file (70 features):",
            type=["csv"],
            help="Upload flow analyzer exports matching the 70 CICIDS2017 feature format."
        )
        if uploaded_file is not None:
            try:
                selected_df = pd.read_csv(uploaded_file)
                input_source_name = uploaded_file.name
            except Exception as e:
                st.error(f"Error reading CSV: {e}")
                
    with tab_sample:
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        if not os.path.exists(data_dir):
            data_dir = r"D:\NIDS_ML_Project\data"
            
        sample_options = {
            "Select a pre-configured sample...": None,
            "01_Benign_Normal_Traffic.csv (25 flows - Normal Traffic)": os.path.join(data_dir, "01_Benign_Normal_Traffic.csv"),
            "02_DDoS_Attack_Traffic.csv (20 flows - DDoS Flood)": os.path.join(data_dir, "02_DDoS_Attack_Traffic.csv"),
            "03_PortScan_Attack_Traffic.csv (20 flows - PortScan Recon)": os.path.join(data_dir, "03_PortScan_Attack_Traffic.csv"),
            "04_DoS_Hulk_Attack_Traffic.csv (20 flows - DoS Hulk)": os.path.join(data_dir, "04_DoS_Hulk_Attack_Traffic.csv"),
            "05_FTP_Patator_BruteForce.csv (20 flows - FTP Brute Force)": os.path.join(data_dir, "05_FTP_Patator_BruteForce.csv"),
            "06_SSH_Patator_BruteForce.csv (15 flows - SSH Brute Force)": os.path.join(data_dir, "06_SSH_Patator_BruteForce.csv"),
            "07_DoS_GoldenEye_Attack.csv (15 flows - DoS GoldenEye)": os.path.join(data_dir, "07_DoS_GoldenEye_Attack.csv"),
            "08_Mixed_Traffic_MultiClass.csv (50 flows - Mixed Traffic Benchmark)": os.path.join(data_dir, "08_Mixed_Traffic_MultiClass.csv"),
            "09_Unlabeled_Live_Capture.csv (30 flows - Unlabeled Real-World Capture)": os.path.join(data_dir, "09_Unlabeled_Live_Capture.csv")
        }
        
        sample_choice = st.selectbox("Choose Benchmark Dataset", list(sample_options.keys()))
        if sample_choice and sample_options[sample_choice]:
            p = sample_options[sample_choice]
            if os.path.exists(p):
                selected_df = pd.read_csv(p)
                input_source_name = os.path.basename(p)
            else:
                st.error("Sample file not located on disk.")
                
    if selected_df is not None:
        st.markdown('<div class="soc-card-title">2. Dataset Profile & Validation Summary</div>', unsafe_allow_html=True)
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Filename", input_source_name)
        c2.metric("Flow Records", f"{len(selected_df):,}")
        c3.metric("Total Columns", len(selected_df.columns))
        
        # Check ground truth
        clean_cols = [c.strip() for c in selected_df.columns]
        has_gt = any(c in clean_cols for c in ["Ground_Truth_Label", "Label", "label", "Class"])
        c4.metric("Ground Truth", "Detected" if has_gt else "Unlabeled")
        
        # Feature Check
        missing_feats = [f for f in feature_names if f not in clean_cols]
        if missing_feats:
            st.error(f"Validation Warning: {len(missing_feats)} expected feature columns are missing from the input.")
        else:
            st.success("Validation Success: All 70 model features are present and verified in dataset.")
            
        with st.expander("Preview Dataset Records (First 10 flows)"):
            st.dataframe(selected_df.head(10), use_container_width=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("ANALYZE NETWORK TRAFFIC", type="primary", use_container_width=True):
            with st.spinner("Executing Random Forest classification & confidence estimation..."):
                results = run_ml_pipeline(selected_df, input_source_name)
                st.success(f"Analysis complete for {len(results)} network flows. Results are ready in the Prediction Results tab.")
                st.balloons() if False else None
    else:
        st.info("Upload a CSV file or choose a benchmark sample above to initiate data profiling.")


# ==========================================
# PAGE 3: PREDICTION RESULTS (CENTRAL FEATURE)
# ==========================================
elif selected_page == "Prediction Results":
    if "results_df" not in st.session_state or st.session_state["results_df"] is None:
        st.info("No predictions available. Please run an analysis on the Traffic Analysis page first.")
    else:
        df_pred = st.session_state["results_df"]
        total_p = len(df_pred)
        malicious_p = int(np.sum(df_pred["Traffic_Type"] == "Malicious"))
        normal_p = total_p - malicious_p
        avg_conf = df_pred["Confidence"].mean()
        
        # KPI Row
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Total Predictions", f"{total_p:,}")
        k2.metric("Threats Flagged", f"{malicious_p:,}", delta=f"{(malicious_p/total_p*100):.1f}%", delta_color="inverse")
        k3.metric("Normal Traffic", f"{normal_p:,}")
        k4.metric("Avg Model Confidence", f"{avg_conf:.1f}%")
        
        if st.session_state.get("has_ground_truth", False) and "Validation_Status" in df_pred.columns:
            matches = int(np.sum(df_pred["Validation_Status"] == "Correct"))
            acc = (matches / total_p) * 100
            st.markdown(f"""
            <div style="padding: 12px 18px; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 6px; margin: 12px 0;">
                <span style="font-weight: 700; color: #4ADE80;">Ground Truth Verification:</span>
                <span style="color: #F8FAFC;"> Model achieved <strong>{acc:.2f}% batch accuracy</strong> ({matches}/{total_p} flows matched ground-truth labels perfectly).</span>
            </div>
            """, unsafe_allow_html=True)
            
        # Featured Spotlight Cards (First 3 Threats or Flows)
        st.markdown('<div class="soc-card-title">Flow Detection Spotlights</div>', unsafe_allow_html=True)
        spot_flows = df_pred[df_pred["Traffic_Type"] == "Malicious"].head(3)
        if spot_flows.empty:
            spot_flows = df_pred.head(3)
            
        scols = st.columns(len(spot_flows))
        for idx, (_, row) in enumerate(spot_flows.iterrows()):
            card_class = "spotlight-threat" if row["Traffic_Type"] == "Malicious" else "spotlight-safe"
            badge_color = "#EF4444" if row["Traffic_Type"] == "Malicious" else "#22C55E"
            with scols[idx]:
                st.markdown(f"""
                <div class="spotlight-card {card_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-size: 13px; font-weight: 700; color: #F8FAFC;">{row['Flow_ID']}</span>
                        <span style="font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 4px; background: {badge_color}; color: #FFFFFF;">{row['Traffic_Type'].upper()}</span>
                    </div>
                    <div style="font-size: 16px; font-weight: 800; color: #F8FAFC; margin-bottom: 4px;">{row['Predicted_Class']}</div>
                    <div style="font-size: 12px; color: #94A3B8;">Confidence: <strong style="color: #F8FAFC;">{row['Confidence']}%</strong></div>
                    <div style="font-size: 12px; color: #94A3B8;">Severity Level: <strong style="color: {SEVERITY_CONFIG.get(row['Predicted_Class'], {}).get('color', '#94A3B8')};">{row['Severity']}</strong></div>
                </div>
                """, unsafe_allow_html=True)
                
        # Interactive Search and Filtering Controls
        st.markdown('<div class="soc-card-title">Interactive Prediction Records Table</div>', unsafe_allow_html=True)
        
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            search_query = st.text_input("Search Flow ID or Port:", "")
        with f2:
            type_filter = st.selectbox("Filter Traffic Type:", ["All Types", "Malicious Only", "Normal Only"])
        with f3:
            all_classes = ["All Categories"] + sorted(list(df_pred["Predicted_Class"].unique()))
            class_filter = st.selectbox("Filter Attack Category:", all_classes)
        with f4:
            sev_filter = st.selectbox("Filter Severity:", ["All Severities", "Low", "Medium", "High", "Critical"])
            
        # Filter Logic
        filtered = df_pred.copy()
        if search_query.strip():
            sq = search_query.strip()
            mask = filtered["Flow_ID"].astype(str).str.contains(sq, case=False)
            if "Destination Port" in filtered.columns:
                mask = mask | filtered["Destination Port"].astype(str).str.contains(sq)
            filtered = filtered[mask]
            
        if type_filter == "Malicious Only":
            filtered = filtered[filtered["Traffic_Type"] == "Malicious"]
        elif type_filter == "Normal Only":
            filtered = filtered[filtered["Traffic_Type"] == "Normal"]
            
        if class_filter != "All Categories":
            filtered = filtered[filtered["Predicted_Class"] == class_filter]
            
        if sev_filter != "All Severities":
            filtered = filtered[filtered["Severity"] == sev_filter]
            
        # Display Table Columns
        table_cols = ["Flow_ID", "Predicted_Class", "Confidence", "Severity", "Traffic_Type"]
        if "Actual_Class" in filtered.columns:
            table_cols += ["Actual_Class", "Validation_Status"]
        if "Destination Port" in filtered.columns:
            table_cols.append("Destination Port")
        if "Flow Duration" in filtered.columns:
            table_cols.append("Flow Duration")
            
        st.write(f"Displaying **{len(filtered)}** of **{len(df_pred)}** flow records:")
        st.dataframe(filtered[table_cols], use_container_width=True, hide_index=True)
        
        # Download Option
        csv_data = filtered.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Filtered Predictions as CSV",
            data=csv_data,
            file_name=f"predictions_{st.session_state.get('dataset_name', 'export')}",
            mime="text/csv"
        )


# ==========================================
# PAGE 4: ATTACK INTELLIGENCE
# ==========================================
elif selected_page == "Attack Intelligence":
    st.markdown('<div class="soc-card-title">Threat Intelligence & Category Analytics</div>', unsafe_allow_html=True)
    
    if "results_df" in st.session_state and st.session_state["results_df"] is not None:
        df_ai = st.session_state["results_df"]
        
        c_left, c_right = st.columns([1, 1])
        with c_left:
            st.markdown("##### Threat Distribution by Category")
            ai_counts = df_ai["Predicted_Class"].value_counts().reset_index()
            ai_counts.columns = ["Attack Category", "Count"]
            ai_bar = px.bar(
                ai_counts,
                x="Count",
                y="Attack Category",
                orientation='h',
                color="Attack Category",
                text="Count"
            )
            ai_bar.update_layout(
                paper_bgcolor='#182235',
                plot_bgcolor='#182235',
                font=dict(color='#F8FAFC'),
                margin=dict(l=20, r=20, t=20, b=20),
                height=300,
                showlegend=False
            )
            st.plotly_chart(ai_bar, use_container_width=True)
            
        with c_right:
            st.markdown("##### Severity Breakdown")
            sev_counts = df_ai["Severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            sev_colors = {'Low': '#22C55E', 'Medium': '#F59E0B', 'High': '#EA580C', 'Critical': '#EF4444'}
            sev_pie = px.pie(
                sev_counts,
                names="Severity",
                values="Count",
                color="Severity",
                color_discrete_map=sev_colors,
                hole=0.5
            )
            sev_pie.update_layout(
                paper_bgcolor='#182235',
                plot_bgcolor='#182235',
                font=dict(color='#F8FAFC'),
                margin=dict(l=20, r=20, t=20, b=20),
                height=300
            )
            st.plotly_chart(sev_pie, use_container_width=True)
            
        if "Destination Port" in df_ai.columns:
            st.markdown("##### Targeted Destination Ports")
            port_counts = df_ai[df_ai["Traffic_Type"] == "Malicious"]["Destination Port"].value_counts().head(8).reset_index()
            port_counts.columns = ["Port", "Attacks Count"]
            port_bar = px.bar(
                port_counts,
                x="Port",
                y="Attacks Count",
                color="Attacks Count",
                color_continuous_scale="Reds"
            )
            port_bar.update_layout(
                paper_bgcolor='#182235',
                plot_bgcolor='#182235',
                font=dict(color='#F8FAFC'),
                margin=dict(l=20, r=20, t=20, b=20),
                height=240,
                coloraxis_showscale=False
            )
            st.plotly_chart(port_bar, use_container_width=True)
            
    # Attack Knowledge Base / Threat Catalog
    st.markdown('<div class="soc-card-title">Threat Intelligence Knowledge Base</div>', unsafe_allow_html=True)
    st.write("Reference documentation for attack categories supported by the Random Forest model:")
    
    for cls_name, info in SEVERITY_CONFIG.items():
        with st.expander(f"{cls_name} — Severity: {info['level']}"):
            st.write(f"**Description:** {info['desc']}")
            if cls_name == "BENIGN":
                st.write("**Operational Status:** Safe network connectivity.")
            elif "DoS" in cls_name or cls_name == "DDoS":
                st.write("**Impact:** High service latency, dropped connections, HTTP 503 gateway timeouts.")
                st.write("**Recommended SOC Action:** Enable upstream IP rate-limiting, activate Web Application Firewall (WAF) challenges, apply TCP SYN cookies.")
            elif "Patator" in cls_name:
                st.write("**Impact:** Compromised administrative accounts via password dictionary brute-force.")
                st.write("**Recommended SOC Action:** Enforce account lockout thresholds, mandate Multi-Factor Authentication (MFA), deploy Fail2Ban.")
            elif cls_name == "PortScan":
                st.write("**Impact:** Unauthorized mapping of open ports and operating system signatures.")
                st.write("**Recommended SOC Action:** Block source IP at perimeter firewall, restrict internal port scanning via network segmentation.")


# ==========================================
# PAGE 5: MODEL PERFORMANCE
# ==========================================
elif selected_page == "Model Performance":
    st.markdown('<div class="soc-card-title">Model Evaluation & Benchmark Metrics</div>', unsafe_allow_html=True)
    
    # Section A: Benchmark Test Set Performance
    st.markdown("### A. Benchmark Evaluation on Held-Out Test Set (499,616 flows)")
    st.write("Rigorous evaluation executed across 8 capture scenarios in the original CICIDS2017 test partition:")
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Random Forest Accuracy", "99.28%")
    m2.metric("Macro Precision", "91.2%")
    m3.metric("Macro Recall", "97.3%")
    m4.metric("Macro F1-Score", "91.4%")
    
    # Algorithm Comparison Chart
    comp_df = pd.DataFrame({
        "Metric": ["Accuracy", "Precision (Weighted)", "Recall (Weighted)", "F1-Score (Weighted)"],
        "Random Forest": [99.28, 99.8, 99.3, 99.5],
        "Decision Tree": [98.17, 98.2, 98.2, 98.1]
    })
    
    fig_comp = go.Figure(data=[
        go.Bar(name='Random Forest (Ensemble)', x=comp_df["Metric"], y=comp_df["Random Forest"], marker_color='#3B82F6'),
        go.Bar(name='Decision Tree (Baseline)', x=comp_df["Metric"], y=comp_df["Decision Tree"], marker_color='#64748B')
    ])
    fig_comp.update_layout(
        barmode='group',
        paper_bgcolor='#182235',
        plot_bgcolor='#182235',
        font=dict(color='#F8FAFC'),
        yaxis=dict(range=[90, 100], title="Percentage (%)", gridcolor='#1E293B'),
        height=280,
        margin=dict(l=20, r=20, t=30, b=20)
    )
    st.plotly_chart(fig_comp, use_container_width=True)
    
    # Classification Report
    st.markdown("##### Official Benchmark Classification Report")
    report_data = [
        {"Traffic Class": "BENIGN", "Precision": 1.00, "Recall": 0.99, "F1-Score": 1.00, "Test Support": "414,468"},
        {"Traffic Class": "Bot", "Precision": 0.12, "Recall": 0.99, "F1-Score": 0.21, "Test Support": "389"},
        {"Traffic Class": "DDoS", "Precision": 1.00, "Recall": 1.00, "F1-Score": 1.00, "Test Support": "25,603"},
        {"Traffic Class": "DoS GoldenEye", "Precision": 0.98, "Recall": 1.00, "F1-Score": 0.99, "Test Support": "2,057"},
        {"Traffic Class": "DoS Hulk", "Precision": 0.99, "Recall": 1.00, "F1-Score": 0.99, "Test Support": "34,569"},
        {"Traffic Class": "DoS Slowhttptest", "Precision": 0.99, "Recall": 0.99, "F1-Score": 0.99, "Test Support": "1,046"},
        {"Traffic Class": "DoS slowloris", "Precision": 0.99, "Recall": 0.99, "F1-Score": 0.99, "Test Support": "1,077"},
        {"Traffic Class": "FTP-Patator", "Precision": 1.00, "Recall": 1.00, "F1-Score": 1.00, "Test Support": "1,186"},
        {"Traffic Class": "Infiltration", "Precision": 1.00, "Recall": 0.67, "F1-Score": 0.80, "Test Support": "9"},
        {"Traffic Class": "PortScan", "Precision": 0.99, "Recall": 1.00, "F1-Score": 0.99, "Test Support": "18,139"},
        {"Traffic Class": "SSH-Patator", "Precision": 0.97, "Recall": 1.00, "F1-Score": 0.98, "Test Support": "644"},
        {"Traffic Class": "Web Attack", "Precision": 0.89, "Recall": 0.99, "F1-Score": 0.94, "Test Support": "429"}
    ]
    st.dataframe(pd.DataFrame(report_data), hide_index=True, use_container_width=True)
    
    st.markdown("---")
    
    # Section B: Current Uploaded Batch Validation
    st.markdown("### B. Current Batch Verification")
    if "results_df" in st.session_state and st.session_state["results_df"] is not None:
        df_batch = st.session_state["results_df"]
        if st.session_state.get("has_ground_truth", False) and "Actual_Class" in df_batch.columns:
            actuals = df_batch["Actual_Class"].astype(str).str.strip().values
            preds = df_batch["Predicted_Class"].astype(str).str.strip().values
            batch_correct = int(np.sum([p.lower() == a.lower() for p, a in zip(preds, actuals)]))
            batch_acc = (batch_correct / len(df_batch)) * 100
            
            b1, b2, b3 = st.columns(3)
            b1.metric("Batch Accuracy", f"{batch_acc:.2f}%")
            b2.metric("Matched Flows", f"{batch_correct:,} / {len(df_batch):,}")
            b3.metric("Discrepancies", f"{len(df_batch) - batch_correct:,}")
            
            # Confusion Heatmap for Batch
            st.markdown("##### Batch Confusion Matrix (Actual vs Predicted)")
            unique_labels = sorted(list(set(actuals) | set(preds)))
            matrix_df = pd.crosstab(
                pd.Series(actuals, name="Actual Ground Truth"),
                pd.Series(preds, name="Model Predicted")
            )
            fig_cm = px.imshow(
                matrix_df,
                text_auto=True,
                color_continuous_scale="Blues",
                aspect="auto"
            )
            fig_cm.update_layout(
                paper_bgcolor='#182235',
                plot_bgcolor='#182235',
                font=dict(color='#F8FAFC'),
                margin=dict(l=20, r=20, t=30, b=20),
                height=340
            )
            st.plotly_chart(fig_cm, use_container_width=True)
        else:
            st.info("Ground-truth labels are not present in the current dataset. The system is operating in live operational inference mode.")
    else:
        st.info("No active dataset loaded. Upload or select a benchmark dataset on the Traffic Analysis page to view batch evaluation.")


# ==========================================
# PAGE 6: REPORTS & EXPORT
# ==========================================
elif selected_page == "Reports":
    st.markdown('<div class="soc-card-title">Security Incident Reporting & Data Export</div>', unsafe_allow_html=True)
    
    if "results_df" not in st.session_state or st.session_state["results_df"] is None:
        st.info("No analyzed dataset available for report compilation. Please analyze a dataset first.")
    else:
        df_rep = st.session_state["results_df"]
        ds_name = st.session_state.get("dataset_name", "network_traffic_capture.csv")
        ts_now = st.session_state.get("analysis_time", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        tot_cnt = len(df_rep)
        norm_cnt = int(np.sum(df_rep["Traffic_Type"] == "Normal"))
        thr_cnt = tot_cnt - norm_cnt
        thr_rate = (thr_cnt / tot_cnt * 100) if tot_cnt > 0 else 0
        
        r1, r2 = st.columns([1, 1])
        
        with r1:
            st.markdown("##### 1. Full Dataset Export (CSV)")
            st.write("Download all 70 raw feature values along with Model Predicted Class, Confidence, Severity, and Traffic Type:")
            csv_exp = df_rep.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Complete Classified Dataset (CSV)",
                data=csv_exp,
                file_name=f"classified_{ds_name}",
                mime="text/csv",
                use_container_width=True
            )
            
        with r2:
            st.markdown("##### 2. Executive Incident Report (PDF)")
            st.write("Generate a formatted SOC Executive Incident Report ready for stakeholder presentation or viva evaluation:")
            
            # Build PDF using ReportLab
            def build_pdf_report():
                buf = io.BytesIO()
                doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
                styles = getSampleStyleSheet()
                
                title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor('#0F172A'), spaceAfter=4)
                sub_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#64748B'), spaceAfter=14)
                h2_style = ParagraphStyle('DocH2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1E293B'), spaceBefore=10, spaceAfter=8)
                norm_style = ParagraphStyle('DocNorm', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#334155'), spaceAfter=6)
                
                story = [
                    Paragraph("NETGUARD AI - Incident Analysis & Threat Report", title_style),
                    Paragraph(f"Network Intrusion Detection System | Generated on {ts_now}", sub_style),
                    Spacer(1, 10),
                    Paragraph("1. Executive Summary", h2_style),
                ]
                
                sum_table_data = [
                    ["Metric Parameter", "Observed Value"],
                    ["Analyzed Capture Filename", ds_name],
                    ["Total Network Flows Evaluated", f"{tot_cnt:,}"],
                    ["Normal (Benign) Flows", f"{norm_cnt:,} ({((norm_cnt/tot_cnt)*100):.1f}%)"],
                    ["Malicious Threats Detected", f"{thr_cnt:,} ({thr_rate:.1f}%)"],
                    ["Threat Risk Classification", "CRITICAL" if thr_rate > 30 else "ELEVATED" if thr_rate > 0 else "NORMAL"],
                    ["Model Engine", "Random Forest Classifier (CICIDS2017 Benchmark - 99.28% Accuracy)"]
                ]
                t_sum = Table(sum_table_data, colWidths=[200, 320])
                t_sum.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ]))
                story.append(t_sum)
                story.append(Spacer(1, 14))
                
                # Attack breakdown table
                story.append(Paragraph("2. Detected Threat Categories", h2_style))
                cat_counts = df_rep["Predicted_Class"].value_counts().reset_index()
                cat_counts.columns = ["Class", "Count"]
                cat_data = [["Traffic Category", "Flow Count", "Proportion", "Assigned Severity"]]
                for _, r in cat_counts.iterrows():
                    c_name = r["Class"]
                    c_cnt = r["Count"]
                    c_pct = f"{(c_cnt / tot_cnt * 100):.1f}%"
                    c_sev = get_severity(c_name)
                    cat_data.append([c_name, str(c_cnt), c_pct, c_sev])
                    
                t_cat = Table(cat_data, colWidths=[160, 110, 110, 140])
                t_cat.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ]))
                story.append(t_cat)
                story.append(Spacer(1, 14))
                
                # Recommendations
                story.append(Paragraph("3. SOC Recommendations", h2_style))
                story.append(Paragraph("• Isolate originating IPs linked to identified volumetric attacks (DDoS, DoS Hulk).", norm_style))
                story.append(Paragraph("• Review perimeter firewall rules and disable legacy port access (Port 21 FTP, 22 SSH).", norm_style))
                story.append(Paragraph("• Verify web application input sanitization against SQL injection and cross-site scripting signatures.", norm_style))
                
                doc.build(story)
                return buf.getvalue()
                
            pdf_bytes = build_pdf_report()
            st.download_button(
                label="Generate & Download SOC Incident PDF Report",
                data=pdf_bytes,
                file_name=f"NETGUARD_Incident_Report_{ds_name.replace('.csv','')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )


# ==========================================
# PAGE 7: ABOUT PROJECT
# ==========================================
elif selected_page == "About Project":
    st.markdown('<div class="soc-card-title">Project Overview & Technical Architecture</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Project Overview
    **NETGUARD AI** is an advanced Network Intrusion Detection System built using Supervised Machine Learning to classify network traffic flows and mitigate cyber intrusions in near real-time.
    
    The system addresses high-volume network security monitoring by evaluating statistical flow parameters extracted from network packet exchanges.
    
    ---
    
    ### Benchmark Dataset: CICIDS2017
    The underlying detection engine is trained on the **CICIDS2017** benchmark dataset provided by the Canadian Institute for Cybersecurity (UNB):
    * **Capture Scope:** 5 full working days of realistic background user traffic combined with modern simulated cyber attacks.
    * **Dataset Size:** Approximately 2.8 million packet flows across 8 CSV capture archives.
    * **Features Extracted:** Generated using **CICFlowMeter**, capturing forward/backward packet counts, inter-arrival times (IAT), packet length statistics, header dimensions, and TCP control flags.
    
    ---
    
    ### Machine Learning Algorithm
    * **Model Architecture:** `Random Forest Classifier` (Ensemble of 100 Decision Trees).
    * **Training / Test Split:** 80% Training partition, 20% Held-out Test partition (499,616 test flows).
    * **Test Accuracy:** **99.28%** (compared to 98.17% for baseline Decision Tree).
    * **Preprocessing:**
      1. Column whitespace sanitization.
      2. Handling of infinite flow rates (`Flow Bytes/s`, `Flow Packets/s`) and missing values.
      3. Feature standardization using `StandardScaler` (zero mean, unit variance).
      4. Multiclass Label Encoding for 12 standardized categories.
      
    ---
    
    ### Monitored Traffic Categories (12 Classes)
    1. **BENIGN:** Legitimate user web, mail, and application traffic.
    2. **Bot:** Ares botnet command-and-control beaconing.
    3. **DDoS:** Distributed Denial of Service packet flood.
    4. **DoS GoldenEye:** HTTP Keep-Alive connection exhaustion.
    5. **DoS Hulk:** Obfuscated high-volume HTTP request flood.
    6. **DoS Slowhttptest:** Slow HTTP read/POST thread starvation.
    7. **DoS slowloris:** Low-and-slow incomplete HTTP header exhaustion.
    8. **FTP-Patator:** Automated dictionary password brute-force targeting Port 21.
    9. **SSH-Patator:** Automated SSH authentication attack targeting Port 22.
    10. **PortScan:** Network reconnaissance probing sequential port states.
    11. **Web Attack:** Application layer SQLi, XSS, and directory brute force.
    12. **Infiltration:** Post-compromise internal network reconnaissance.
    
    ---
    
    ### Technology Stack
    * **Language:** Python 3.11
    * **Framework:** Streamlit
    * **Core Libraries:** Scikit-Learn, Pandas, NumPy, Plotly, ReportLab, Joblib
    """)
