# Automated SOC Incident Report Generator

This is a cybersecurity project I built while learning about SOC operations and threat intelligence.

The idea is simple: enter a suspicious IP address, check it using the VirusTotal API, and get the important information in one place. The application also generates a PDF report based on the analysis.

## What does it do?

The application allows me to:

- Enter an IP address
- Check the IP using VirusTotal
- See how many security engines marked it as malicious or harmless
- View the country and network/ISP information
- Get a basic threat verdict
- Generate a PDF incident report

## Why I built this

While learning about SOC analysis, I noticed that checking an IP address can involve looking at different pieces of information and then documenting the result.

I wanted to build a small tool that combines some of these steps into one simple dashboard.

This project also helped me practice working with APIs, Python, Streamlit, JSON data, and PDF generation.

## Technologies I used

- Python
- Streamlit
- VirusTotal API
- Requests
- FPDF

## How it works

Enter IP Address
       ->
VirusTotal API
       ->
Get Threat Information
       ->
Analyze the Result
       ->
Display Result
       ->
Generate PDF Report
