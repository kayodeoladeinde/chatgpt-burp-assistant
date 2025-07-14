# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IMessageEditorTabFactory, IMessageEditorTab, IScanIssue
from java.util import ArrayList
from javax.swing import JPanel, JComboBox, JButton, JScrollPane, JTextArea, BoxLayout, JMenuItem
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json

# Replace with your actual OpenAI API key
OPENAI_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

class BurpExtender(IBurpExtender, IContextMenuFactory, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ChatGPT Burp Assistant")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)
        return

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Ask ChatGPT", actionPerformed=lambda e: self.handle_context(invocation, "prompt")))
        menu_list.add(JMenuItem("Analyze & Report Issue", actionPerformed=lambda e: self.handle_context(invocation, "issue")))
        return menu_list

    def handle_context(self, invocation, mode):
        try:
            req_resp = invocation.getSelectedMessages()[0]
            request = self._helpers.bytesToString(req_resp.getRequest())
            if mode == "prompt":
                prompt_text = "Please analyze this HTTP request:\n\n" + request
                response = self.ask_chatgpt(prompt_text)
                self._callbacks.issueAlert("ChatGPT response:\n\n" + response)
            else:
                prompt_text = (
                    "Analyze the following HTTP request for vulnerabilities and use CVSS-like logic to rate severity "
                    "based on exploitability, impact, and ease of use. "
                    "If you detect a vulnerability, respond in JSON with fields: title, severity (Low/Medium/High/Critical), "
                    "description, and remediation.\n\n"
                    + request
                )
                response = self.ask_chatgpt(prompt_text)
                data = json.loads(response)
                self.report_issue(data, req_resp)
                self._callbacks.issueAlert("Reported issue: " + data.get("title", "Unnamed"))
        except Exception as ex:
            self._callbacks.issueAlert("Error: " + str(ex))

    def report_issue(self, data, req_resp):
        sev = data.get("severity", "Information").capitalize()
        sev_map = {"Information":"Information","Low":"Low","Medium":"Medium","High":"High","Critical":"High"}
        issue = CustomScanIssue(
            req_resp.getHttpService(),
            self._helpers.analyzeRequest(req_resp).getUrl(),
            [req_resp],
            data.get("title", "Unnamed"),
            data.get("description", ""),
            sev_map.get(sev, "Information"),
            data.get("remediation", "")
        )
        self._callbacks.addScanIssue(issue)

    def createNewInstance(self, controller, editable):
        return ChatGPTTab(self, controller, editable)

    def ask_chatgpt(self, prompt):
        try:
            url = URL("https://api.openai.com/v1/chat/completions")
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Authorization", "Bearer " + OPENAI_API_KEY)
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)

            body = json.dumps({
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.4
            })

            writer = OutputStreamWriter(conn.getOutputStream())
            writer.write(body)
            writer.flush()
            writer.close()

            code = conn.getResponseCode()
            stream = conn.getInputStream() if code < 400 else conn.getErrorStream()
            reader = BufferedReader(InputStreamReader(stream))
            resp = ""
            line = reader.readLine()
            while line:
                resp += line
                line = reader.readLine()
            reader.close()

            data = json.loads(resp)
            if code >= 400:
                err = data.get("error", {}).get("message", resp)
                return json.dumps({"error":"[HTTP %d] %s" % (code, err)})
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            return json.dumps({"error":"Extension error: "+str(e)})

class ChatGPTTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._controller = controller

        # UI setup
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.dropdown = JComboBox(["Suggest XSS Payload","Analyze Auth Headers","Write Report Summary","Analyze & Report Issue"])
        self.send_button = JButton("Send to ChatGPT", actionPerformed=self.send_prompt)

        self.chat_area = JTextArea(15,70)
        self.chat_area.setLineWrap(True)
        self.chat_area.setWrapStyleWord(True)
        chat_scroll = JScrollPane(self.chat_area)

        self.context_area = JTextArea(5,70)
        self.context_area.setLineWrap(True)
        self.context_area.setWrapStyleWord(True)
        context_scroll = JScrollPane(self.context_area)

        self.context_button = JButton("Explain this Issue", actionPerformed=self.explain_issue)

        self.panel.add(self.dropdown)
        self.panel.add(self.send_button)
        self.panel.add(chat_scroll)
        self.panel.add(context_scroll)
        self.panel.add(self.context_button)

    def getTabCaption(self): return "ChatGPT Assistant"
    def isEnabled(self, content, isRequest): return True
    def setMessage(self, content, isRequest): pass
    def getMessage(self): return None
    def isModified(self): return False
    def getSelectedData(self): return self.chat_area.getSelectedText()
    def getUiComponent(self): return self.panel

    def send_prompt(self, event):
        req_resp = self._controller
        request = self._helpers.bytesToString(req_resp.getRequest())
        task = self.dropdown.getSelectedItem()
        if task == "Suggest XSS Payload":
            prompt = "Suggest XSS payloads for this HTTP request:\n\n" + request
        elif task == "Analyze Auth Headers":
            prompt = "Analyze auth headers of this request:\n\n" + request
        elif task == "Write Report Summary":
            prompt = "Write a vulnerability report summary based on this request and response:\n\n" + request
        else:
            prompt = ( "Analyze this HTTP request for vulnerabilities with CVSS-like severity.\n\n" + request )
            response = self._extender.ask_chatgpt(prompt)
            data = json.loads(response)
            self._extender.report_issue(data, req_resp)
            self.chat_area.setText("Issue added: " + data.get("title","Unnamed"))
            return
        response = self._extender.ask_chatgpt(prompt)
        self.chat_area.setText(response)

    def explain_issue(self, event):
        req_resp = self._controller
        request = self._helpers.bytesToString(req_resp.getRequest())
        context = self.context_area.getText().strip()
        prompt = ("You are a cybersecurity expert. Analyze this HTTP request and user notes. "
                  "Use CVSS-like logic. Respond in JSON: title,severity,description,remediation.\n\n"
                  "Request:\n" + request + "\n\nNotes:\n" + context)
        response = self._extender.ask_chatgpt(prompt)
        self.chat_area.setText(response)

class CustomScanIssue(IScanIssue):
    def __init__(self,http_service,url,http_messages,name,detail,severity,remediation):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._remediation = remediation
    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Firm"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return self._remediation
    def getHttpMessages(self): return self._http_messages
    def getHttpService(self): return self._http_service
