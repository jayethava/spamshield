"""
SpamShield: Model Training & Evaluation Pipeline
================================================
Trains TF-IDF + Multinomial Naive Bayes and Logistic Regression models
on SMS Spam Collection dataset augmented with Indian-context scams.
Compares both models, evaluates performance, and persists the winner with joblib.
"""

import os
import json
import re
import urllib.request
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'model')
SPAM_CSV = os.path.join(DATA_DIR, 'spam.csv')
INDIAN_SCAMS_CSV = os.path.join(DATA_DIR, 'indian_scams.csv')
MODEL_PATH = os.path.join(MODEL_DIR, 'spam_detector.joblib')
METRICS_PATH = os.path.join(MODEL_DIR, 'metrics.json')


def clean_text(text: str) -> str:
    """
    Standardize text while preserving scam signal indicators
    (currencies, phone numbers, URLs, urgent punctuation).
    """
    if not isinstance(text, str):
        return ""
    
    # Normalize URLs to a uniform token
    text = re.sub(r'https?://\S+|www\.\S+', ' http_url ', text)
    # Normalize email addresses
    text = re.sub(r'\S+@\S+', ' email_addr ', text)
    # Normalize phone numbers / long digits
    text = re.sub(r'\+?\d[\d -]{8,}\d', ' phone_num ', text)
    # Normalize currency references
    text = re.sub(r'(?:rs\.?|inr|₹|\$|£|€)\s*\d+', ' money_amount ', text, flags=re.IGNORECASE)
    # Lowercase
    text = text.lower()
    # Remove excessive non-alphanumeric symbols but retain whitespace
    text = re.sub(r'[^a-z0-9_\s]', ' ', text)
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def load_and_prepare_data():
    """
    Load primary SMS dataset + Indian scams dataset, clean text, and encode labels.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)

    # 1. Check or download primary dataset
    if not os.path.exists(SPAM_CSV):
        print("[*] spam.csv not found locally. Attempting download from public repository...")
        urls = [
            'https://raw.githubusercontent.com/stedy/Machine-Learning-with-R-datasets/master/sms_spam.csv',
            'https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv'
        ]
        downloaded = False
        for u in urls:
            try:
                urllib.request.urlretrieve(u, SPAM_CSV)
                print(f"[+] Successfully downloaded dataset from {u}")
                downloaded = True
                break
            except Exception as e:
                print(f"[-] Could not download from {u}: {e}")
        
        if not downloaded:
            raise FileNotFoundError("Could not find or download spam.csv dataset.")

    # Read primary dataset (handling different column naming conventions)
    try:
        df_primary = pd.read_csv(SPAM_CSV, encoding='utf-8')
    except UnicodeDecodeError:
        df_primary = pd.read_csv(SPAM_CSV, encoding='latin-1')

    # Standardize column names
    col_map = {}
    for col in df_primary.columns:
        c_low = col.lower().strip()
        if c_low in ['type', 'v1', 'label', 'category', 'target']:
            col_map[col] = 'label'
        elif c_low in ['text', 'v2', 'message', 'sms', 'content']:
            col_map[col] = 'text'
    df_primary = df_primary.rename(columns=col_map)[['label', 'text']]

    # 2. Load Indian-specific scams augmentation dataset if available
    dfs = [df_primary]
    if os.path.exists(INDIAN_SCAMS_CSV):
        print(f"[+] Augmenting training set with {INDIAN_SCAMS_CSV}...")
        try:
            df_indian = pd.read_csv(INDIAN_SCAMS_CSV, encoding='utf-8')
            if 'label' in df_indian.columns and 'text' in df_indian.columns:
                dfs.append(df_indian[['label', 'text']])
            elif 'type' in df_indian.columns and 'text' in df_indian.columns:
                df_indian = df_indian.rename(columns={'type': 'label'})
                dfs.append(df_indian[['label', 'text']])
        except Exception as e:
            print(f"[-] Warning: Failed to read indian_scams.csv: {e}")

    df_combined = pd.concat(dfs, ignore_index=True).dropna(subset=['label', 'text'])

    # Standardize labels to binary: 0 = ham (safe), 1 = spam
    df_combined['label'] = df_combined['label'].astype(str).str.strip().str.lower()
    df_combined['target'] = df_combined['label'].apply(lambda x: 1 if 'spam' in x else 0)

    # Clean raw text
    df_combined['clean_text'] = df_combined['text'].apply(clean_text)
    # Remove empty texts after cleaning
    df_combined = df_combined[df_combined['clean_text'].str.len() > 0].reset_index(drop=True)

    print(f"[i] Dataset loaded: Total samples = {len(df_combined)} "
          f"(Ham: {(df_combined['target'] == 0).sum()}, Spam: {(df_combined['target'] == 1).sum()})")

    return df_combined


def train_models():
    """
    Trains Naive Bayes and Logistic Regression, evaluates both,
    computes explainability weights, and saves best artifacts.
    """
    df = load_and_prepare_data()

    X = df['clean_text']
    y = df['target']

    # Stratified 80/20 split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

    # TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words='english',
        sublinear_tf=True
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Model 1: Multinomial Naive Bayes
    nb_model = MultinomialNB(alpha=0.1)
    nb_model.fit(X_train_vec, y_train)
    nb_preds = nb_model.predict(X_test_vec)

    # Model 2: Logistic Regression
    lr_model = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    lr_model.fit(X_train_vec, y_train)
    lr_preds = lr_model.predict(X_test_vec)

    def compute_metrics(y_true, y_pred, model_name):
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        return {
            'model_name': model_name,
            'accuracy': float(accuracy_score(y_true, y_pred)),
            'precision': float(precision_score(y_true, y_pred, zero_division=0)),
            'recall': float(recall_score(y_true, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_true, y_pred, zero_division=0)),
            'confusion_matrix': {
                'tn': int(tn),
                'fp': int(fp),
                'fn': int(fn),
                'tp': int(tp),
                'raw': [[int(tn), int(fp)], [int(fn), int(tp)]]
            },
            'classification_report': classification_report(y_true, y_pred, output_dict=True)
        }

    nb_eval = compute_metrics(y_test, nb_preds, "Multinomial Naive Bayes")
    lr_eval = compute_metrics(y_test, lr_preds, "Logistic Regression")

    # Pick winner based on F1-score (or accuracy if tied)
    if nb_eval['f1_score'] >= lr_eval['f1_score']:
        winner_name = "Multinomial Naive Bayes"
        winner_model = nb_model
        winner_metrics = nb_eval
        runner_metrics = lr_eval
    else:
        winner_name = "Logistic Regression"
        winner_model = lr_model
        winner_metrics = lr_eval
        runner_metrics = nb_eval

    # Compute word-level log odds / weights for Explainable AI
    feature_names = vectorizer.get_feature_names_out()
    word_weights = {}

    if isinstance(winner_model, MultinomialNB):
        # Log likelihood difference: log P(w|spam) - log P(w|ham)
        # feature_log_prob_[1] is spam, [0] is ham
        spam_log_prob = winner_model.feature_log_prob_[1]
        ham_log_prob = winner_model.feature_log_prob_[0]
        log_odds = spam_log_prob - ham_log_prob
        for word, score in zip(feature_names, log_odds):
            word_weights[word] = float(score)
    else:
        # Logistic regression coefficients
        coefs = winner_model.coef_[0]
        for word, score in zip(feature_names, coefs):
            word_weights[word] = float(score)

    # Sort top spam indicator words
    top_spam_words = sorted(word_weights.items(), key=lambda item: item[1], reverse=True)[:50]

    # Package payload to save with joblib
    saved_payload = {
        'model': winner_model,
        'vectorizer': vectorizer,
        'model_name': winner_name,
        'feature_names': feature_names.tolist(),
        'word_weights': word_weights,
        'classes': [0, 1]
    }
    joblib.dump(saved_payload, MODEL_PATH)

    # Metrics summary JSON for frontend dashboard & reports
    metrics_summary = {
        'winner': winner_name,
        'dataset_stats': {
            'total_samples': len(df),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'ham_count': int((df['target'] == 0).sum()),
            'spam_count': int((df['target'] == 1).sum()),
            'vocabulary_size': len(feature_names)
        },
        'models': {
            'naive_bayes': nb_eval,
            'logistic_regression': lr_eval
        },
        'best_model': winner_metrics,
        'top_spam_indicators': [{'word': w, 'weight': round(s, 3)} for w, s in top_spam_words[:20]]
    }

    with open(METRICS_PATH, 'w', encoding='utf-8') as f:
        json.dump(metrics_summary, f, indent=2)

    # Console display output
    print("\n" + "=" * 65)
    print("           SPAMSHIELD MODEL EVALUATION REPORT")
    print("=" * 65)
    print(f"{'Metric':<20} | {'Multinomial NB':<18} | {'Logistic Regression':<18}")
    print("-" * 65)
    print(f"{'Accuracy':<20} | {nb_eval['accuracy']*100:>16.2f}% | {lr_eval['accuracy']*100:>16.2f}%")
    print(f"{'Precision (Spam)':<20} | {nb_eval['precision']*100:>16.2f}% | {lr_eval['precision']*100:>16.2f}%")
    print(f"{'Recall (Spam)':<20} | {nb_eval['recall']*100:>16.2f}% | {lr_eval['recall']*100:>16.2f}%")
    print(f"{'F1-Score':<20} | {nb_eval['f1_score']*100:>16.2f}% | {lr_eval['f1_score']*100:>16.2f}%")
    print("-" * 65)
    print(f"[*] SELECTED MODEL: {winner_name} (Saved to {MODEL_PATH})")
    print("-" * 65)
    print("\nConfusion Matrix (Best Model):")
    cm = winner_metrics['confusion_matrix']
    print(f"  True Negative (Legit -> Legit): {cm['tn']:<5} | False Positive (Legit -> Spam): {cm['fp']:<5}")
    print(f"  False Negative (Spam -> Legit): {cm['fn']:<5} | True Positive (Spam -> Spam):   {cm['tp']:<5}")

    print("\nTop 10 Spam Predictive Keywords:")
    for i, (word, weight) in enumerate(top_spam_words[:10], 1):
        print(f"  {i:>2}. {word:<20} (+{weight:.2f})")
    print("=" * 65 + "\n")

    return metrics_summary


if __name__ == '__main__':
    train_models()
