import matplotlib
matplotlib.use("Agg")
import pandas as pd, numpy as np, joblib
import matplotlib.pyplot as plt, seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             confusion_matrix, roc_curve, roc_auc_score)
from xgboost import XGBClassifier


def main():
    ALL_FEATURES = [
     "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
     "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
     "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
     "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
     "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
     "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
     "Statistical_report"
    ]
    # These need paid APIs, so they are not used for live prediction
    DROP = ["web_traffic","Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report"]

    url = "https://raw.githubusercontent.com/npapernot/phishing-detection/master/dataset.csv"
    df = pd.read_csv(url, header=None)
    df = df.iloc[:, -31:]                      # 30 features + Result
    df.columns = ALL_FEATURES + ["Result"]
    df["Result"] = df["Result"].map({-1: 1, 1: 0})   # 1 = Phishing, 0 = Legitimate

    feature_names = [c for c in ALL_FEATURES if c not in DROP]
    X = df[feature_names]
    y = df["Result"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    xgb_model = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                              subsample=0.8, colsample_bytree=0.8,
                              eval_metric="logloss", random_state=42)
    xgb_model.fit(X_train, y_train)

    y_pred = xgb_model.predict(X_test)
    y_prob = xgb_model.predict_proba(X_test)[:, 1]
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    print(f"Accuracy: {accuracy*100:.2f}%  Precision: {precision*100:.2f}%  Recall: {recall*100:.2f}%  AUC: {auc:.4f}")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(5,4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Oranges",
                xticklabels=["Legitimate","Phishing"], yticklabels=["Legitimate","Phishing"])
    plt.xlabel("Predicted"); plt.ylabel("Actual"); plt.title("Confusion Matrix - XGBoost")
    plt.tight_layout(); plt.savefig("confusion_matrix.png", dpi=120); plt.close()

    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.figure(figsize=(6,5))
    plt.plot(fpr, tpr, label=f"XGBoost (AUC = {auc:.3f})", color="#DD8452")
    plt.plot([0,1],[0,1], linestyle="--", color="gray")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC Curve"); plt.legend()
    plt.tight_layout(); plt.savefig("roc_curve.png", dpi=120); plt.close()

    # Feature importance
    imp = pd.Series(xgb_model.feature_importances_, index=feature_names).sort_values(ascending=False)
    plt.figure(figsize=(8,8))
    imp.head(15).plot(kind="barh", color="#DD8452")
    plt.gca().invert_yaxis(); plt.title("Top 15 Important Features"); plt.xlabel("Importance Score")
    plt.tight_layout(); plt.savefig("feature_importance.png", dpi=120); plt.close()

    joblib.dump(xgb_model, "phishing_xgboost_model.pkl")
    joblib.dump(feature_names, "feature_names.pkl")
    joblib.dump({"accuracy": accuracy, "precision": precision, "recall": recall, "auc": auc}, "metrics.pkl")
    print("Model and all files saved successfully")


if __name__ == "__main__":
    main()
