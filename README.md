# chatgpt-burp-assistant
Burp Suite extension that integrates ChatGPT for automated vulnerability analysis, payload suggestions, and issue reporting with severity tagging. Boosts AppSec workflows using AI. Built in Jython, easy to extend and use in Burp Professional.
# Specifically 
ChatGPT Burp Assistant is a Python (Jython) extension for Burp Suite Professional that lets you:
Suggest XSS/SSRF payloads
Analyze HTTP auth headers
Generate vulnerability report summaries
Auto-create Burp issues with CVSS-like severity
Explain issues using custom context notes
# How to Use the ChatGPT Burp Assitant
Open Burp Suite Professional
Launch your Burp Suite app (ensure you're using the Professional version).
Load the Extension
Go to the Extender tab → Extensions sub-tab.
Click "Add".
Set the Extension type to Python.
Click Select file and choose the chatgpt_burp_full_extension_final_fixed2.py file you want to load.
Click Next to finish loading the extension.
Set Your OpenAI API Key in the .py file
# Start Using It
After loading, you’ll see a “ChatGPT Assistant” tab in Burp.
Right-click any request → use options like "Ask GPT", "Analyze for Vuln", etc.
You can also interact with the extension tab to ask questions, generate payloads, or create report content.
