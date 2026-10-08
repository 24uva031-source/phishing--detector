import os
import streamlit as st
import pandas as pd
import joblib
from features import extract_features

st.set_page_config(page_title="Phishing Website Detector", page_icon="🛡️", layout="wide")

os.chdir(os.path.dirname(os.path.abspath(__file__)))
NEEDED = ["phishing_xgboost_model.pkl", "feature_names.pkl", "metrics.pkl",
          "confusion_matrix.png", "roc_curve.png", "feature_importance.png"]
if not all(os.path.exists(f) for f in NEEDED):
    with st.spinner("First start: training the model (about 1 minute)..."):
        import train_model
        train_model.main()

model = joblib.load("phishing_xgboost_model.pkl")
feature_names = joblib.load("feature_names.pkl")
metrics = joblib.load("metrics.pkl")

st.title("Phishing Website Detection System")
st.markdown("**Algorithm:** XGBoost Classifier + Rule-based Red Flag Check")

tab1, tab2 = st.tabs(["Predict", "Model Performance"])

with tab1:
    st.subheader("Enter a Website URL")
    url_input = st.text_input("Website URL", placeholder="https://example.com")

    if st.button("Check Website", use_container_width=True, type="primary"):
        if not url_input.strip():
            st.warning("Please enter a URL")
        else:
            try:
                with st.spinner("Analysing website..."):
                    feats = extract_features(url_input)
                    input_df = pd.DataFrame([feats])[feature_names]
                    pred = int(model.predict(input_df)[0])
                    prob = float(model.predict_proba(input_df)[0][1])  # phishing probability

                flags = []
                if feats["having_IP_Address"] == -1: flags.append("URL-la IP address irukku")
                if feats["having_At_Symbol"] == -1: flags.append("URL-la @ symbol irukku")
                if feats["Shortining_Service"] == -1: flags.append("URL shortener use panniruku")
                if feats["Prefix_Suffix"] == -1: flags.append("Domain-la '-' irukku")
                if feats["SSLfinal_State"] == -1: flags.append("HTTPS illa / SSL problem")
                if feats["age_of_domain"] == -1: flags.append("Domain romba pudhusu / WHOIS info illa")
                if feats["DNSRecord"] == -1: flags.append("DNS record illa")
                if not feats["_fetched"]: flags.append("Page open aagala (site dead / blocked)")

                if pred == 1:
                    st.error(f"PHISHING WEBSITE DETECTED - Confidence: {prob*100:.2f}%")
                elif len(flags) >= 3:
                    st.warning(f"SUSPICIOUS - Model legitimate-nu sonnalum {len(flags)} red flags irukku")
                else:
                    st.success(f"LEGITIMATE WEBSITE - Confidence: {(1-prob)*100:.2f}%")
                st.progress(prob)

                if flags:
                    st.write("**Red flags:**")
                    for fl in flags:
                        st.write("- " + fl)

                with st.expander("Extracted features"):
                    feat_df = pd.DataFrame({
                        "Feature": feature_names,
                        "Value": [int(input_df.iloc[0][c]) for c in feature_names]
                    })
                    st.table(feat_df)
            except Exception as e:
                st.error(f"Could not analyse this URL: {e}")

with tab2:
    st.subheader("Model Performance Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Accuracy", f"{metrics['accuracy']*100:.2f}%")
    c2.metric("Precision", f"{metrics['precision']*100:.2f}%")
    c3.metric("Recall", f"{metrics['recall']*100:.2f}%")
    c4.metric("AUC Score", f"{metrics['auc']:.4f}")

    colA, colB = st.columns(2)
    with colA:
        st.image("confusion_matrix.png", caption="Confusion Matrix")
    with colB:
        st.image("roc_curve.png", caption="ROC Curve")
    st.image("feature_importance.png", caption="Top 15 Important Features")