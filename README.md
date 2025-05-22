# Unravelling-AI-Driven-Phishing-Email-Detection
## Email Phishing Detection

This project is a web-based application designed to detect phishing emails by analyzing email content, sender domains, and embedded URLs. It integrates a custom-trained BERT-based deep learning model, achieving an accuracy of 87.1%, with VirusTotal’s API to provide a robust phishing detection system. This allows users to identify and manage potentially malicious emails directly from their Gmail inbox.

## Project Overview

Welcome to my project! This web-based application safeguards your Gmail inbox from phishing threats by leveraging a custom Fine tuned BERT model, achieving an impressive 87.1% accuracy, alongside VirusTotal’s API for comprehensive threat detection. It fetches emails via IMAP, analyzes their content, sender domains, and URLs, and classifies them as SAFE, SUSPICIOUS, or PHISHING. Emails flagged as risky are automatically moved to the spam folder, ensuring a safer email experience. The app features a modern, dark-themed interface with real-time updates and a user-friendly design.

Key Features
-Gmail Integration: Connects securely to Gmail using IMAP and an app-specific password.

-Email Listing: Displays emails with pagination, showing sender, subject, date, and content preview.

-Phishing Detection:

-Custom-trained BERT model (87.1% accuracy) analyzes email content for phishing patterns.

-VirusTotal API scans sender domains and URLs for malicious activity.

-Combined analysis classifies emails as SAFE, SUSPICIOUS, or PHISHING.

-Automatic Spam Management: Moves SUSPICIOUS or PHISHING emails to the Gmail spam folder.

-Real-Time Email Streaming: Checks for new emails every 10 seconds using Server-Sent Events (SSE).

-Responsive UI: Features a dark-themed interface with animations and a loading indicator for scan results.

-Secure Session Management: Uses Flask sessions with HTTPS and secure cookie settings.























