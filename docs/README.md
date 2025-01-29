# DeepEyE AI Assistant for Burp Suite

![logo](./docs/images/logo.png)

## Description

DeepEyE AI Assistant is an extension for Burp Suite designed to assist cybersecurity professionals in analyzing HTTP requests and responses for security vulnerabilities. It leverages artificial intelligence to provide detailed analysis and exploitation suggestions.

## Features

- **Request Analysis**: Analyzes HTTP requests to identify potential security issues.
- **Response Analysis**: Examines HTTP responses to detect unusual behaviors that may indicate vulnerabilities.
- **Vulnerability Search**: Combines request and response analysis to search for common vulnerabilities such as injections, XSS, SSRF, and more.
- **Intuitive User Interface**: Provides a user-friendly interface within Burp Suite for easy interaction with the extension.

## Installation

1. **Prerequisites**:
   - Burp Suite
   - Jython (to run Python scripts in Burp Suite)
   - Ollama
   - DeepSeek

2. **Setup**:
   - Clone this repository or download the necessary files.
   - Ensure Jython is installed and configured in Burp Suite.
   - Install Ollama and DeepSeek on your system.

3. **Import the Extension**:
   - Open Burp Suite.
   - Go to the "Extender" tab.
   - Click "Add".
   - Select "Extension type" as "Python".
   - Navigate to the `burp_extender.py` file in the `src` folder and select it.

## Usage

- **Request Analysis**: Click the "Analyze Request" button to analyze the current HTTP request.
- **Response Analysis**: Click the "Analyze Response" button to analyze the current HTTP response.
- **Vulnerability Search**: Use the "Analyze Request and Response for Search Vulns" button for a comprehensive vulnerability analysis.

## Model Configuration

The extension uses a specific AI model for analysis. If you need to change the model, follow these steps:

1. Open the `deep_eye_repeater_tab.py` file located in the `src` directory.
2. Locate the `send_to_DeepEyE` method.
3. Modify the `"model"` field in the `payload` dictionary to the desired model name. For example:
   ```python
   payload = json.dumps({
       "model": "your-new-model-name",
       "messages": [{"role": "user", "content": prompt}],
       "temperature": 0.7
   })
   ```
4. Save the changes and restart Burp Suite to apply the new model configuration. 