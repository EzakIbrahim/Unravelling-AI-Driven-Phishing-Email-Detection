# Unravelling-AI-Driven-Phishing-Email-Detection
## Email Phishing Detection

This project is a web-based application designed to detect phishing emails by analyzing email content, sender domains, and embedded URLs. It integrates a custom-trained BERT-based deep learning model, achieving an accuracy of 87.1%, with VirusTotal’s API to provide a robust phishing detection system. This allows users to identify and manage potentially malicious emails directly from their Gmail inbox.

## Project Overview

Welcome to my project! This web-based application safeguards your Gmail inbox from phishing threats by leveraging a custom Fine tuned BERT model, achieving an impressive 87.1% accuracy, alongside VirusTotal’s API for comprehensive threat detection. It fetches emails via IMAP, analyzes their content, sender domains, and URLs, and classifies them as SAFE, SUSPICIOUS, or PHISHING. Emails flagged as risky are automatically moved to the spam folder, ensuring a safer email experience. The app features a modern, dark-themed interface with real-time updates and a user-friendly design.

## Key Features
- Gmail Integration: Connects securely to Gmail using IMAP and an app-specific password.

- Email Listing: Displays emails with pagination, showing sender, subject, date, and content preview.

 #### Phishing Detection:

- Custom-trained BERT model (87.1% accuracy) analyzes email content for phishing patterns.

- VirusTotal API scans sender domains and URLs for malicious activity.

- Combined analysis classifies emails as SAFE, SUSPICIOUS, or PHISHING.

- Automatic Spam Management: Moves SUSPICIOUS or PHISHING emails to the Gmail spam folder.

- Real-Time Email Streaming: Checks for new emails every 10 seconds using Server-Sent Events (SSE).

- Responsive UI: Features a dark-themed interface with animations and a loading indicator for scan results.

- Secure Session Management: Uses Flask sessions with HTTPS and secure cookie settings.


## How It Works

Login: Users log in to their Gmail account using an app-specific password.

Inbox View: Emails are fetched via IMAP and displayed in a paginated interface, showing sender, subject, date, and a content preview.

### Email Analysis:

 #### View Email: Open an email to see its full content.

 #### Scan Email: 

Triggers a multi-layered analysis:

Text Analysis: The BERT model evaluates the email body for phishing indicators.

Domain Check: VirusTotal scans the sender’s domain for malicious reputation.

URL Check: VirusTotal scans URLs in the email for potential threats.

Classification: Combines results to classify the email as SAFE, SUSPICIOUS, or PHISHING.

Automatic Spam Management: Non-safe emails are moved to the Gmail spam folder.

Real-Time Updates: The app checks for new emails every 10 seconds via SSE.

## BERT Model Details

The core of the phishing detection system is a BERT (Bidirectional Encoder Representations from Transformers) deep learning model, personally trained by the project creator. Key details:

**Model Type**: BERT-based model fine-tuned for phishing email detection.

**Training**: Trained on a dataset of labeled phishing and non-phishing emails, achieving an accuracy of 87.1% on the test set.

**Functionality**: Analyzes the email body (cleaned of URLs and special characters) to detect phishing patterns using bidirectional context understanding.

**Implementation**: Uses Hugging Face’s AutoTokenizer and AutoModelForSequenceClassification for tokenization and classification, with a confidence threshold of 0.2 for phishing detection.

**Integration**: Combines BERT’s phishing probability with VirusTotal’s domain and URL scan results for accurate classification.

## VirusTotal Integration

The project uses the VirusTotal API to enhance phishing detection without requiring a custom reputation system. VirusTotal aggregates threat intelligence from multiple antivirus engines and security vendors to:

**Scan Sender Domains**: Extracts the domain from the sender’s email (e.g., `@example.com`) and checks its reputation using VirusTotal’s `/domains` endpoint, excluding Gridinsoft for adjusted malicious counts.

**Scan URLs**: Identifies URLs in the email body and scans them using VirusTotal’s `/urls` and `/analyses` endpoints to detect malicious or suspicious links.

**Result Aggregation**: Combines VirusTotal’s results with the BERT model’s text analysis for a comprehensive classification.

## Why No Need for a Reputation System

VirusTotal provides a robust reputation system by aggregating results from dozens of antivirus engines and threat intelligence sources. Building a custom reputation system would be redundant and resource-intensive, requiring maintenance of a database of malicious domains and URLs. By using VirusTotal, the project benefits from up-to-date threat intelligence, allowing it to focus on email fetching, BERT-based content analysis, and user experience.

# Setup Instructions

## Clone the Repository:
`git clone https://github.com/your-username/email-phishing-detection.git`

`cd email-phishing-detection`

## Install Dependencies: Ensure Python 3.8+ is installed, then set up a virtual environment and install requirements:
`python -m venv venv`

`source venv/bin/activate  # On Windows: venv\Scripts\activate`

`pip install flask email-validator requests torch transformers`

## Set Up VirusTotal API Keys:

- Sign up for a VirusTotal account and obtain API keys at VirusTotal.

- Update the API_KEYS list in app.py:

`API_KEYS = ["your_api_key_1", "your_api_key_2"]`

## Set Up SSL Certificates:
- Install mkcert from mkcert GitHub. 

- Generate SSL certificates for local development:
`mkcert 127.0.0.1`














