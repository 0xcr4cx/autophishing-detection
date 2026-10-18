# 🛡️ Automated Phishing Email Detection Using Local AI

A Python-based phishing detection tool that combines locally hosted AI with VirusTotal threat intelligence to analyze suspicious emails and identify potential phishing attempts.

The tool processes emails saved in `.eml` format, uses a locally running Ollama model to analyze email content, and leverages the VirusTotal API to check the credibility of URLs. The results are returned in structured JSON format for easy interpretation and further automation.

## Features

- **Email Analysis:** Analyzes suspicious emails provided in `.eml` format.
- **Local AI Integration:** Uses Ollama to run an AI model locally for phishing detection.
- **Threat Intelligence:** Integrates the VirusTotal API to check URLs against known threat intelligence.
- **Structured JSON Output:** Produces machine-readable JSON results for consistent reporting and potential integration with security tools.
- **Python Automation:** Automates the email analysis process through a Python script.
- **Privacy-Focused Analysis:** Uses a locally hosted AI model for email analysis, reducing the need to send email content to an external AI service.

## Technologies Used

- **Python** — Core scripting and automation.
- **Ollama** — Local AI model execution and inference.
- **VirusTotal API** — URL reputation and threat intelligence checks.
- **JSON** — Structured output for analysis results.
- **EML** — Email file format used as the input source.

## ⚙️ How It Works

1. **Input:** Provide a suspicious email saved in `.eml` format.
2. **Email Parsing:** The Python script extracts relevant email information and content for analysis.
3. **AI Analysis:** The locally running Ollama model evaluates the email for suspicious characteristics and potential phishing indicators.
4. **Threat Intelligence Lookup:** The VirusTotal API checks relevant URLs against its threat intelligence database.
5. **Result Generation:** The system combines the analysis into a structured JSON output.

## Purpose:
Exploring the VirusToatal, Ollama and its restrictions. 
