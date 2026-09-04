# Context
I am trying to build an AI local agent that can handle basic SIEM alerts investigations. The input will be from the alerts SIEM generates and the final output is a report on that alert with the neccesary information, enrichment and recommended actions. The AI model used will be fully local on a 24GB MacBook Pro.

# Planned modules in the app
The app should have a few distinct modules with their own functions.
## Integration module
This module handles the integration needed with the SIEM platform. It should be able to handle various types of auth (Basic, Bearer token etc). After connection, it needs to be able to pull alerts from the SIEM. To investigate tehse alerts, it should also have several functions that are needed for basic investigation and enrinchment such as: search, query etc (suggest and expand as needed)
## Alert Tracking and Reporting
This is where the alerts input and output will sit. After the integration module pulls the alert from the SIEM, raw alerts will sit here. Downstream modules will pull alerts from here to report. After the investigation is done, the final report will be put here as well. 
## Agentic Analyst
This is the main module where all the investigation happens. Alerts will be pulled from Alert Tracking and Reporting module and investigation starts. The agent will first understand what the alert is about. Then, it will atempt enrichment of the alert, this can either be querying the SIEM agein, and use the tools available in the enrinchment module. It has to determine what data point is worth investigation and to use the correct tool for it.
## Enricnment module
This module will handle the external tools that the Agentic Analyst module will use. This will include platform like AbuseIPDB, virustotal and more. It should handle auth too.

# Requirements
## Modularity
The entire system should be designed with modularity in mind so that different stack could be used with the core functionalities. The SIEM could be different and different enrinchment platform may be integrated.
## Local AI Agent Usage
As this system is designed to be used with Local LLMs, care should be taken to make sure that the decision points in the agentic flow is compatible with the small models. It should be tightly scoped to prevent hallucination as much as possible.

# Demo Stack
Below is the stack for the initial demo for this agent.
SIEM: Wazuh
LLM inference: Undecided
LLM Model: Undecided
Language: Python