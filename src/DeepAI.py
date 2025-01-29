# -*- coding: utf-8 -*-

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.io import PrintWriter, BufferedReader, InputStreamReader, OutputStreamWriter
from java.net import URL, HttpURLConnection
from java.awt import BorderLayout
from javax.swing import JPanel, JButton, JTextArea, JTextField, JScrollPane, SwingUtilities
import json
import threading

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Console output
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # Register extension
        callbacks.setExtensionName("DeepEyE AI Assistant for Repeater")

        # Register custom tab inside Repeater
        callbacks.registerMessageEditorTabFactory(self)

        self.chat_history = {}  # Store chat per request

        self.stdout.println("[+] DeepEyE AI Assistant loaded successfully!")

    def createNewInstance(self, controller, editable):
        return DeepEyERepeaterTab(self, controller, editable, self)

class DeepEyERepeaterTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable, burp_extender):
        self._extender = extender
        self._helpers = extender._helpers
        self._controller = controller
        self._editable = editable
        self._burp_extender = burp_extender
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(True)

        # UI Panel inside Repeater
        self.panel = JPanel(BorderLayout())
        self.chat_area = JTextArea(12, 50)
        self.chat_area.setEditable(False)
        self.scroll_pane = JScrollPane(self.chat_area)

        # Input field for user to type messages
        self.input_field = JTextField(40)

        # Buttons
        self.analyze_request_button = JButton("Analyze Request")
        self.analyze_response_button = JButton("Analyze Response")
        self.search_vulns_button = JButton("Analyze Request and Response for Search Vulns")
        self.send_button = JButton("Send")

        # Attach event listeners
        self.analyze_request_button.addActionListener(self.analyze_request)
        self.analyze_response_button.addActionListener(self.analyze_response)
        self.search_vulns_button.addActionListener(self.search_vulns)
        self.send_button.addActionListener(self.send_user_message)
        self.input_field.addActionListener(self.send_user_message)

        button_panel = JPanel()
        button_panel.add(self.analyze_request_button)
        button_panel.add(self.analyze_response_button)
        button_panel.add(self.search_vulns_button)

        input_panel = JPanel()
        input_panel.add(self.input_field)
        input_panel.add(self.send_button)

        self.panel.add(self.scroll_pane, BorderLayout.CENTER)
        self.panel.add(input_panel, BorderLayout.NORTH)
        self.panel.add(button_panel, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "DeepEyE AI"

    def getUiComponent(self):
        return self.panel

    def isEnabled(self, content, isRequest):
        return True  # Enable for both requests and responses

    def isModified(self):
        return False  # Required for Burp, prevents errors

    def getMessage(self):
        return None  # No need to return modified content

    def getSelectedData(self):
        return None  # Not supporting selection modifications

    def setMessage(self, content, isRequest):
        """ Loads chat history for the current request when switching tabs. """
        if content is None:
            self._txtInput.setText(None)
            return

        request_info = self._helpers.analyzeRequest(content)
        headers = request_info.getHeaders()
        body = content[request_info.getBodyOffset():].tostring().decode("utf-8", "ignore")
        self._request_text = "\n".join(headers) + "\n\n" + body

        self._current_content = content  # Store the request for later analysis

        # Load chat history (persistent)
        request_id = hash(self._request_text)
        if request_id in self._burp_extender.chat_history:
            self.chat_area.setText(self._burp_extender.chat_history[request_id])
        else:
            self.chat_area.setText("AI Assistant ready. Ask about this request.\n")

    def analyze_request(self, event=None):
        """ AI analyzes the current request for security issues. """
        self.update_chat("User > Analyze this request for security issues.\n", True)
        threading.Thread(target=self.send_to_DeepEyE, args=("Analyze this HTTP request:\n\n" + self._request_text, False)).start()

    def analyze_response(self, event=None):
        """ AI analyzes the current response for security issues. """
        response = self._controller.getResponse()
        if response:
            response_text = self._helpers.bytesToString(response)
            self.update_chat("User > Analyze this response for security issues.\n", True)
            threading.Thread(target=self.send_to_DeepEyE, args=("Analyze this HTTP response:\n\n" + response_text, False)).start()
        else:
            self.update_chat("Error: No response available for analysis.\n", True)

    def search_vulns(self, event=None):
        """ AI searches for vulnerabilities based on both request and response. """
        response = self._controller.getResponse()
        if response:
            response_text = self._helpers.bytesToString(response)
            prompt = (
                "You are a highly skilled cybersecurity expert with extensive experience in web application security, "
                "penetration testing, and vulnerability analysis. Your task is to analyze the following HTTP request "
                "and response extracted from Burp Suite's Repeater tool. Carefully examine the request structure, "
                "headers, parameters, and payloads, as well as the response behavior, status codes, headers, and body "
                "content to identify potential security vulnerabilities.\n\n"
                "Look for indicators of the following security flaws, but not limited to:\n\n"
                "Injection Attacks: SQL Injection (SQLi), NoSQL Injection, Command Injection, LDAP Injection, XML "
                "External Entity Injection (XXE).\n"
                "Cross-Site Scripting (XSS): Reflected, Stored, DOM-Based.\n"
                "Server-Side Request Forgery (SSRF): Blind SSRF, Open Redirect SSRF, SSRF via headers.\n"
                "Broken Access Control & IDOR: Unauthorized access to sensitive data, insecure direct object references, "
                "privilege escalation vectors.\n"
                "File Inclusion & Path Traversal: Local File Inclusion (LFI), Remote File Inclusion (RFI), directory "
                "traversal exploits.\n"
                "Remote Code Execution (RCE) & Deserialization Attacks: Identifying insecure deserialization, command "
                "injection points, or improper handling of user-controlled input leading to code execution.\n"
                "Authentication & Session Management Issues: Session fixation, token leakage, improper authorization "
                "mechanisms, weak JWT tokens, and cookie security misconfigurations.\n"
                "Business Logic & Rate Limiting Bypasses: Testing for logical flaws that allow unintended actions, lack "
                "of rate limiting, and automation abuse risks.\n"
                "Information Disclosure: Stack traces, error messages, sensitive keys in responses, internal IP addresses, "
                "API endpoints leaks.\n\n"
                "Provide a detailed analysis of any suspicious elements found, including potential exploitation techniques, "
                "payload suggestions. Focus on unusual behaviors in the response that could indicate an underlying security flaw. If needed, suggest additional manual testing "
                "approaches or automation techniques to further confirm the presence of a vulnerability.\n\n"
                "Request:\n" + self._request_text +
                "\n\nResponse:\n" + response_text +
                "\n\nIdentify any potential security issues and suggest ways to exploit, payloads and PoCs to exploit them."
            )
            self.update_chat("User > Searching vulnerabilities based on request and response...\n", True)
            threading.Thread(target=self.send_to_DeepEyE, args=(prompt, False)).start()
        else:
            self.update_chat("Error: No response available for vulnerability search.\n", True)

    def send_user_message(self, event=None):
        """ Sends user input to AI and updates chat. """
        user_message = self.input_field.getText().strip()
        if user_message:
            self.update_chat("User > " + user_message + "\n", True)
            self.input_field.setText("")  # Clear input field
            threading.Thread(target=self.send_to_DeepEyE, args=("Current HTTP request:\n\n" + self._request_text + "\n\nUser query:\n" + user_message, False)).start()

    def send_to_DeepEyE(self, prompt, modify_request):
        """ Sends the request to DeepEyE AI asynchronously. """
        try:
            url = URL("http://localhost:11434/v1/chat/completions")
            connection = url.openConnection()
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Authorization", "Bearer DeepEyE")
            connection.setDoOutput(True)

            payload = json.dumps({
                "model": "deepseek-r1:1.5b",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            })

            output_stream = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            output_stream.write(payload)
            output_stream.close()

            input_stream = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
            response_text = input_stream.readLine()
            input_stream.close()

            response_json = json.loads(response_text)
            ai_response = response_json["choices"][0]["message"]["content"]
            self.update_chat("DeepEyE AI > " + ai_response + "\n", True)

        except Exception as e:
            self.update_chat("Error in DeepEyE request: " + str(e) + "\n", True)

    def update_chat(self, text, new_line):
        """ Updates the chat area asynchronously and saves history. """
        def append_text():
            if new_line:
                self.chat_area.append("\n")
            self.chat_area.append(text)
            self.chat_area.setCaretPosition(self.chat_area.getDocument().getLength())

        SwingUtilities.invokeLater(append_text)
