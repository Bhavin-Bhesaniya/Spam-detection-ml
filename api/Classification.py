import re
import requests
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from urlextract import URLExtract
import torch
import time
import pickle
import string
import joblib
import pandas as pd
import nltk
import os
import mimetypes
from nltk.corpus import stopwords
import re

tfidf = pickle.load(open('Model/vectorizer.pkl','rb'))
model_names = ['rfmodel.pkl', 'knmodel.pkl', 'gbdtmodel.pkl','mnbmodel.pkl']
models = {model_name: joblib.load(f'Model/{model_name}') for model_name in model_names}

# Default model
# fine_tune_model = pickle.load(open('Model/fine_tuned_model.pkl', 'rb'))
# fine_tune_tokenizer = pickle.load(open('Model/fine_tuned_tokenizer.pkl', 'rb'))

YOUR_API_KEY = os.environ.get('VIRUS_TOTAL_API_KEY')


def extract_ip_addresses(email_content):
    ip_addresses = []
    ipv4_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
    
    ipv4_addresses = re.findall(ipv4_pattern, email_content)
    ip_addresses.extend(ipv4_addresses)
    
    ipv6_addresses = re.findall(ipv6_pattern, email_content)
    ip_addresses.extend(ipv6_addresses)
    return ip_addresses


def check_malicious_ip(ip_address, YOUR_API_KEY):
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": YOUR_API_KEY
        }
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()
        malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        if malicious_count > 0:
            return True
        else:
            return False
        
    except Exception as e:
        return str(e)


def check_malicious_link(url, YOUR_API_KEY):
    try:
        headers={
            "accept": "application/json",
            "x-apikey": YOUR_API_KEY
        }
    
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        response.raise_for_status()
        data = response.json()       
        id = data.get("data", {}).get("id")

        if id:
            time.sleep(10)
        
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{id}")
            data = response.json()
        
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_count > 0:    
                return True
            else:
                return False
        else:
            result_message = "Error: Invalid response data structure"
            return result_message
        
    except Exception as e:
        return str(e)


def scan_attachment(file_instance, YOUR_API_KEY):
    try:
        file_name = file_instance.name
        file_complete_content = file_instance.read()
        file_type, _ = mimetypes.guess_type(file_name)
        if not file_type:
            file_type = "application/octet-stream"
        

        url = "https://www.virustotal.com/api/v3/files"
        
        headers = {
            "accept": "application/json",
            "x-apikey": YOUR_API_KEY,
        }
        
        files = {"file": (file_name,file_complete_content,file_type)}
        response = requests.post(url, files=files, headers=headers)
        response.raise_for_status()

        data = response.json()    
        if "data" in data:
            id = data["data"].get("id")
            if id:
                time.sleep(20)
                
                report_url = f"https://www.virustotal.com/api/v3/analyses/{id}"
                response = requests.get(report_url, headers=headers)
                response.raise_for_status()
                data = response.json()
            
                malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                return "Malicious attachment" if malicious_count > 0 else "Not Malicious attachment"
            else:
                return "Error: Invalid response data structure"
        else:
            return "Error: Invalid response data structure"
    
    except Exception as e:
        print(f"Error analyzing attachment :  {str(e)}")
        return str(e)


def transform_text(text):
    text = text.lower()
    text = nltk.word_tokenize(text)
    y = []
    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            if i.isalnum():
                y.append(i)
    return " ".join(y)
    

def classify_with_selected_model(email_content, select_model):
    user_data = []
    
    transformed_text = transform_text(email_content)
    vector_input = tfidf.transform([transformed_text])
        
    if select_model in models:
        select_model = models[select_model]
        result = select_model.predict(vector_input)[0]
        result_message = "Spam, " if result == 1 else "Not spam, "
        
        existing_data = pd.read_csv("Model/user_insert_value.csv")
        if not existing_data[(existing_data['target'] == result) & (existing_data['text'] == email_content)].empty:
            return result_message
        else:
            user_data.append({'target': result, 'text': email_content})
            df = pd.DataFrame(user_data)
            df.to_csv("Model/user_insert_value.csv", mode='a', header=False, index=False)
            return result_message
    # else:
    #     return classify_with_default_model(email_content)


# def classify_with_default_model(email_content):
#     inputs = fine_tune_tokenizer(email_content, return_tensors="pt", padding=True, truncation=True, max_length=128) 
#     with torch.no_grad():
#         outputs = fine_tune_model(**inputs)
#         logits = outputs.logits
#     result = torch.argmax(logits, dim=1).item()
#     result_message = "Spam, " if result == 1 else "Not spam, "
#     return result_message
        

def classify_spam(email_content, user_selected_model=None, file_instance=None):
    final_output = []    
    if user_selected_model is not None:
        result_message = classify_with_selected_model(email_content, user_selected_model)
        final_output.append(result_message)
    # else:
    #     result_message = classify_with_default_model(email_content)
    #     final_output.append(result_message)


    url_pattern = r'(https?://(?:www\.)?[a-zA-Z0-9]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?/?[^\s]*)'
    links = re.findall(url_pattern, email_content)

    for link in links:
        if check_malicious_link(link, YOUR_API_KEY):
            final_output.append(f"Malicious link detected, {link}")
        else:
            final_output.append(f"All links safe, {link} ")


    extracted_ips = extract_ip_addresses(email_content)
    for ip in extracted_ips:
        if check_malicious_ip(ip, YOUR_API_KEY):
            final_output.append(f"Malicious IP address detected: {ip}")
        else:
            final_output.append(f"IP address {ip} is safe")
       

    if file_instance is not None:
        result_message = scan_attachment(file_instance, YOUR_API_KEY)
        final_output.append(result_message)
    

    return "\n".join(final_output)
