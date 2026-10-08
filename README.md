# SpamShield: Explainable SMS & Email Spam/Scam Detector
> **College Python Mini Project** — A full-stack, Explainable AI (XAI) cybersecurity web application that detects and explains SMS and email scams with 98.84% accuracy.

![SpamShield Status](https://img.shields.io/badge/Model%20Accuracy-98.84%25-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Framework](https://img.shields.io/badge/Framework-Flask%203-lightgrey)
![ML](https://img.shields.io/badge/ML-scikit--learn-orange)
![Database](https://img.shields.io/badge/Database-SQLite-blueviolet)

---

## 📌 Project Overview
Phishing, financial scams, and fraudulent messages are responsible for billions in losses annually. Traditional spam filters act as opaque "black boxes" that output a label without justification.

**SpamShield** provides **Explainable Threat Intelligence**:
1. **Machine Learning Pipeline**: Trained on 5,615 SMS messages (UCI SMS Spam Collection augmented with localized Indian cyber fraud patterns like SBI YONO KYC, KBC lotteries, electricity power cut alerts, and work-from-home tasks).
2. **Explainable AI (XAI)**: Calculates mathematical log-odds ratios $\log P(w|\text{spam}) - \log P(w|\text{ham})$ to visually highlight influential spam trigger words with red opacity proportional to impact.
3. **Cybersecurity Link Scanner**: Dissects embedded URLs to flag raw IP addresses, URL shorteners, disposable TLDs (`.xyz`, `.top`, `.buzz`), excessive subdomains, and credential theft keywords (`kyc`, `verify`, `login`).
4. **Actionable Security Guidance**: Generates contextual defense recommendations based on detected scam categories.

---

## 🛠️ Tech Stack
- **Backend**: Python 3, Flask
- **Machine Learning**: `scikit-learn` (TF-IDF Vectorization, Multinomial Naive Bayes, Logistic Regression), `joblib`, `pandas`, `numpy`
- **Database**: SQLite3 (`database.db`) with native query layer
- **Frontend**: HTML5, Modern CSS3 (Glassmorphism, Dark/Light Mode toggle, CSS variables), Vanilla JavaScript, Chart.js (bundled locally for 100% offline support)

---

## 📂 Project Structure
```
spamshield/
├── app.py                     # Main Flask web application & REST API routes
├── train.py                   # Data ingestion, preprocessing, ML training & benchmarking
├── detector.py                # Inference engine, XAI log-odds attribution, Link Scanner
├── database.py                # SQLite database layer, audit history & analytics aggregation
├── requirements.txt           # Project dependencies
├── README.md                  # Comprehensive documentation & demo script
├── database.db                # SQLite database (auto-generated)
├── data/
│   ├── spam.csv               # UCI SMS Spam Collection dataset (5,574 samples)
│   ├── indian_scams.csv       # Curated Indian fraud patterns & balanced samples
│   └── sample_bulk.csv        # Ready-to-use CSV template for bulk scanning demo
├── model/
│   ├── spam_detector.joblib   # Serialized best model & TF-IDF vectorizer
│   └── metrics.json           # Benchmark metrics, confusion matrix & word weights
├── templates/
│   ├── base.html              # Layout shell, navigation, dark/light theme switcher
│   ├── index.html             # Check Message page, circular risk gauge, XAI highlighter
│   ├── history.html           # Past checks ledger, filter, search & CSV export
│   ├── dashboard.html         # Chart.js visualizations & model evaluation metrics
│   ├── bulk.html              # Drag-and-drop CSV batch analyzer
│   └── about.html             # Presentation architecture & College Viva Voce guide
└── static/
    ├── css/
    │   └── style.css          # Glassmorphism design system, responsive layout
    └── js/
        ├── chart.min.js       # Bundled Chart.js v4.4 (works completely offline)
        ├── main.js            # Live analysis, SVG gauge animation, sample loaders
        ├── dashboard.js       # Chart.js charts initialization
        └── bulk.js            # Batch file upload, progress, CSV export
```

---

## 🚀 Quickstart & Setup Guide

### Step 1: Install Dependencies
Open PowerShell or Terminal inside the `spamshield` directory:
```bash
pip install -r requirements.txt
```

### Step 2: Train and Benchmark the ML Models
Run the training pipeline. It evaluates Multinomial Naive Bayes and Logistic Regression, selects the winner, and saves model artifacts:
```bash
python train.py
```
*Expected Console Output:*
```
=================================================================
           SPAMSHIELD MODEL EVALUATION REPORT
=================================================================
Metric               | Multinomial NB     | Logistic Regression
-----------------------------------------------------------------
Accuracy             |            98.84% |            97.95%
Precision (Spam)     |            97.35% |            97.84%
Recall (Spam)        |            94.23% |            87.18%
F1-Score             |            95.77% |            92.20%
-----------------------------------------------------------------
[*] SELECTED MODEL: Multinomial Naive Bayes
Confusion Matrix (Best Model):
  True Negative (Legit -> Legit): 963   | False Positive (Legit -> Spam): 4    
  False Negative (Spam -> Legit): 9     | True Positive (Spam -> Spam):   147  
=================================================================
```

### Step 3: Run the Web Application
You can run SpamShield using either **Flask** or **Streamlit**:

#### Option A: Streamlit (Interactive Data Science UI)
```bash
streamlit run streamlit_app.py
```
Open your browser at: **`http://localhost:8501`**

#### Option B: Flask (Full-Stack Custom Web UI)
```bash
python app.py
```
Open your browser at: **`http://127.0.0.1:5000`**

---

## ☁️ Deploying to Streamlit Community Cloud (Free Online Hosting)
To share your project online with examiners or recruiters via a public web link:
1. Push this project folder to your GitHub repository (e.g., `https://github.com/your-username/spamshield`).
2. Visit **[share.streamlit.io](https://share.streamlit.io)** and sign in with GitHub.
3. Click **"New app"**.
4. Select your repository, set Main file path to **`streamlit_app.py`**, and click **"Deploy"**.
5. Your app will be live on a public URL (e.g. `https://spamshield-detector.streamlit.app`)!

---

## 🎯 3-Minute College Presentation Demo Script

### Minute 0:00 - 0:45 | Introduction & Problem Statement
1. **Show Landing Page (`http://127.0.0.1:5000`)**:
   > *"Good morning/afternoon Professors. Today I am presenting **SpamShield**, an explainable AI system for SMS and email scam detection. Traditional spam blockers give a binary score without explaining why. SpamShield provides word-level explainability and deep link cybersecurity scanning."*
2. Toggle the **Dark/Light Mode** button at the top-right to demonstrate the modern glassmorphism interface.

### Minute 0:45 - 1:45 | Live Test with Scam Messages & Explainable AI
1. Click the **"SBI KYC Phishing"** quick sample button.
   - Text loaded: `Dear SBI Customer, your YONO account has been suspended due to pending PAN KYC. Click http://sbi-kyc-update.xyz/verify immediately...`
   - Click **"Analyze Message"**.
   - **Show the Result Card**:
     - **Verdict**: `SPAM` (Risk Score: `98%`, Confidence: `99.2%`).
     - **Category**: `Fake KYC / Banking`.
     - **Explainable AI Box**: Point out how words like `"suspended"`, `"verify"`, and `"kyc"` are highlighted in red with tooltips displaying their statistical spam weights.
     - **Why Flagged List**: Review the top 5 trigger keywords and explanations.
     - **Link Scanner**: Notice the link `http://sbi-kyc-update.xyz/verify` flagged as **Malicious** because of the `.xyz` high-risk TLD, phishing keyword `"verify"`, and insecure HTTP protocol.
     - **Safety Tips**: RBI banking advice generated dynamically.
2. Click **"KBC 25 Lakh Lottery"** sample or **"Power Cut Notice"** to show instant category switching and accuracy.
3. Click **"Safe: Personal Chat"** or **"Safe: Food Delivery"** to prove the model does not trigger false alarms on legitimate text (Verdict: `SAFE`, Risk Score: `0%`).

### Minute 1:45 - 2:30 | Batch Processing & History Audit
1. Navigate to **Bulk Scanner** (`/bulk`).
2. Click **"Download Sample CSV Template"**, then drag-and-drop the file into the scanner dropzone.
3. Click **"Start Bulk Analysis"**. Show how 10 mixed messages are categorized in real-time, then click **"Download Predictions CSV"** to demonstrate downloadable reporting.
4. Navigate to **History** (`/history`) to show the persistent SQLite ledger with keyword search, verdict filters, and the detail inspection modal.

### Minute 2:30 - 3:00 | Dashboard & ML Evaluation Benchmarks
1. Navigate to **Dashboard** (`/dashboard`).
2. Highlight the interactive Chart.js visualizations (Verdict breakdown, category distribution, activity timeline).
3. Scroll to the **Confusion Matrix & Model Comparison Table**:
   > *"We compared Multinomial Naive Bayes against Logistic Regression using 5-fold stratification. Naive Bayes achieved 98.84% accuracy and 95.77% F1-score with only 4 false positives out of 967 legitimate test messages."*
4. Click **About & Viva Guide** (`/about`) to demonstrate the TF-IDF math breakdown and viva cheatsheet.

---

## 🧪 5 Verification Test Messages

| # | Type | Message Content | Expected Verdict | Expected Category |
|---|---|---|---|---|
| 1 | **Scam (KYC Phishing)** | `Dear SBI Customer, your YONO account has been suspended due to pending PAN KYC. Click http://sbi-kyc-update.xyz/verify immediately to avoid deactivation.` | **SPAM** (98%) | Fake KYC / Banking |
| 2 | **Scam (Lottery)** | `Congratulations! Your mobile number has won Rs 25,00,000 in KBC Kaun Banega Crorepati WhatsApp Lucky Draw. Call Rana Pratap Singh on +919876543210 to claim prize.` | **SPAM** (99%) | Lottery / Reward Scam |
| 3 | **Scam (Electricity Cut)** | `Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please call electricity officer at 9876543210 immediately.` | **SPAM** (97%) | Electricity Bill Disconnection |
| 4 | **Safe (Personal)** | `Hey Rahul, are we meeting for the project discussion in library at 4 PM today? Let me know.` | **SAFE** (0%) | Safe / Legitimate |
| 5 | **Safe (Order Alert)** | `Swiggy: Your order from Biryani Blues is on the way! Delivery partner Manoj is arriving in 12 mins. Track live in your Swiggy app.` | **SAFE** (0%) | Safe / Legitimate |

---

## 🧠 Viva Voce Q&A Cheat Sheet for Students

1. **Why Multinomial Naive Bayes over Deep Learning?**
   - For short SMS text (15-30 words), Multinomial Naive Bayes achieves near-perfect accuracy (98.84%) with sub-2 millisecond latency on low-resource hardware without GPU dependencies.
2. **What does TF-IDF represent?**
   - TF (Term Frequency) scores how often a term appears in a message. IDF (Inverse Document Frequency) downweights universally common words like `"is"` or `"the"` while elevating distinctive threat words like `"kyc"` or `"crorepati"`.
3. **How does Laplace Smoothing ($\alpha=0.1$) assist?**
   - In standard Naive Bayes, if an incoming message contains a previously unseen word, its probability would be zero, nullifying the entire product. Laplace smoothing adds $\alpha$ to all feature counts to prevent zero-probability errors.
4. **How is Explainable AI (XAI) implemented?**
   - SpamShield extracts the log-likelihood ratio for each token: $\log P(w|\text{spam}) - \log P(w|\text{ham})$. Positive scores indicate how strongly a specific token pulled the decision boundary toward spam, which is then mapped to visual opacity.

---

## 📄 License & Attribution
- SMS Spam Collection dataset courtesy of UCI Machine Learning Repository (Almeida et al.).
- Built for educational mini-project demonstration.
