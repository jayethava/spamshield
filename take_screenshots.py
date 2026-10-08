"""
Captures high-resolution screenshots of SpamShield for the college project report.
Uses Selenium WebDriver with Microsoft Edge in headless mode.
"""

import time
import os
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

DOCS_DIR = os.path.join(os.path.dirname(__file__), 'docs_images')
os.makedirs(DOCS_DIR, exist_ok=True)

edge_options = Options()
edge_options.add_argument('--headless=new')
edge_options.add_argument('--disable-gpu')
edge_options.add_argument('--window-size=1400,1050')
edge_options.add_argument('--no-sandbox')
edge_options.add_argument('--disable-dev-shm-usage')

driver = webdriver.Edge(options=edge_options)

try:
    print("[*] Navigating to SpamShield Streamlit App (http://localhost:8501)...")
    driver.get("http://localhost:8501")
    time.sleep(5)  # Wait for Streamlit React hydration

    # 1. Landing Page Screenshot
    path_1 = os.path.join(DOCS_DIR, '01_spamshield_landing_page.png')
    driver.save_screenshot(path_1)
    print(f"[+] Saved screenshot 1: {path_1}")

    # 2. Select a scam sample and analyze
    print("[*] Selecting sample scam message...")
    # Find selectbox or textarea
    textareas = driver.find_elements(By.TAG_NAME, "textarea")
    if textareas:
        textareas[0].clear()
        textareas[0].send_keys("Dear SBI Customer, your YONO account has been suspended due to pending PAN KYC. Click http://sbi-kyc-update.xyz/verify immediately to avoid permanent deactivation.")
        time.sleep(1)

        # Click analyze button
        buttons = driver.find_elements(By.TAG_NAME, "button")
        for b in buttons:
            if "Analyze Message" in b.text:
                b.click()
                break
        
        print("[*] Waiting for ML inference and XAI rendering...")
        time.sleep(4)

        path_2 = os.path.join(DOCS_DIR, '02_spam_detected_explainable_ai.png')
        driver.save_screenshot(path_2)
        print(f"[+] Saved screenshot 2: {path_2}")

    # 3. Test Safe Message
    print("[*] Testing safe message...")
    textareas = driver.find_elements(By.TAG_NAME, "textarea")
    if textareas:
        textareas[0].clear()
        textareas[0].send_keys("Hi Mom, I will reach home by 7 PM today. Please keep dinner ready.")
        time.sleep(1)

        buttons = driver.find_elements(By.TAG_NAME, "button")
        for b in buttons:
            if "Analyze Message" in b.text:
                b.click()
                break
        
        time.sleep(4)
        path_3 = os.path.join(DOCS_DIR, '03_safe_message_analysis.png')
        driver.save_screenshot(path_3)
        print(f"[+] Saved screenshot 3: {path_3}")

    # 4. Analytics Dashboard
    print("[*] Navigating to Analytics Dashboard...")
    radio_labels = driver.find_elements(By.XPATH, "//label[contains(., 'Analytics Dashboard')]")
    if radio_labels:
        radio_labels[0].click()
        time.sleep(3)
        path_4 = os.path.join(DOCS_DIR, '04_analytics_dashboard_metrics.png')
        driver.save_screenshot(path_4)
        print(f"[+] Saved screenshot 4: {path_4}")

    # 5. Bulk Scanner
    print("[*] Navigating to Bulk Scanner...")
    bulk_labels = driver.find_elements(By.XPATH, "//label[contains(., 'Bulk Scanner')]")
    if bulk_labels:
        bulk_labels[0].click()
        time.sleep(3)
        path_5 = os.path.join(DOCS_DIR, '05_bulk_scanner_interface.png')
        driver.save_screenshot(path_5)
        print(f"[+] Saved screenshot 5: {path_5}")

    print("[SUCCESS] All screenshots captured successfully!")

except Exception as e:
    print(f"[-] Error capturing screenshots: {e}")
finally:
    driver.quit()
