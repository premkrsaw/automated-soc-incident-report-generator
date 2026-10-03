import streamlit as st
import requests
from fpdf import FPDF
import os
from datetime import datetime

# Web Page Title aur Icon
st.set_page_config(page_title="AutoSOC Dashboard", page_icon="🛡️")

#  API KEY OF VIRUSTOTAL
VT_API_KEY = st.secrets["VT_API_KEY"]


# FUNCTION 1: PDF GENERATOR
def generate_pdf(ip_address, malicious_score, harmless_score, country, owner):
    pdf = FPDF()
    pdf.add_page()
    
    # 1. Report Header
    pdf.set_font("Arial", style='B', size=18)
    pdf.cell(200, 10, txt="DIGITAL FORENSICS & INCIDENT RESPONSE", ln=True, align='C')
    pdf.set_font("Arial", style='B', size=14)
    pdf.cell(200, 10, txt="Automated SOC Threat Intelligence Report", ln=True, align='C')
    
    pdf.line(10, 30, 200, 30)
    pdf.ln(15)
    
    # 2. Scan Metadata Section
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.set_font("Arial", style='B', size=12)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(200, 10, txt="1. TARGET METADATA", ln=True)
    pdf.set_text_color(0, 0, 0)
    
    pdf.set_font("Courier", size=11)
    pdf.cell(200, 8, txt=f"[*] Target IP Address : {ip_address}", ln=True)
    pdf.cell(200, 8, txt=f"[*] Date & Time       : {current_time}", ln=True)
    pdf.cell(200, 8, txt=f"[*] Registered Owner  : {owner}", ln=True)
    pdf.cell(200, 8, txt=f"[*] Geolocation       : {country}", ln=True)
    pdf.ln(5)
    
    # 3. Threat Assessment Section
    pdf.set_font("Arial", style='B', size=12)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(200, 10, txt="2. THREAT ASSESSMENT SCORES", ln=True)
    pdf.set_text_color(0, 0, 0)
    
    pdf.set_font("Courier", size=11)
    pdf.cell(200, 8, txt=f"[+] Malicious Flags   : {malicious_score}", ln=True)
    pdf.cell(200, 8, txt=f"[+] Harmless Flags    : {harmless_score}", ln=True)
    pdf.ln(5)
    
    # 4. Final Verdict & Action Plan
    pdf.set_font("Arial", style='B', size=12)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(200, 10, txt="3. FINAL VERDICT & SOC RECOMMENDATION", ln=True)
    
    pdf.set_font("Arial", style='B', size=11)
    if malicious_score > 0:
        pdf.set_text_color(255, 0, 0)
        pdf.cell(200, 8, txt="VERDICT: CRITICAL THREAT DETECTED", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 8, txt="Action Plan: Immediately block this IP on the perimeter firewall. Isolate any internal endpoints that have established a connection with this IP address and initiate a full malware scan.")
    else:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(200, 8, txt="VERDICT: CLEAN (No active threats detected)", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 8, txt="Action Plan: No immediate action required. Continue standard network monitoring.")
        
    file_name = f"SOC_Report_{ip_address}.pdf"
    pdf.output(file_name)
    return file_name



# FUNCTION 2: VIRUSTOTAL SCANNER
def check_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        
        country = data['data']['attributes'].get('country', 'Unknown')
        owner = data['data']['attributes'].get('as_owner', 'Unknown')
        
        return {
            "success": True, 
            "malicious": stats['malicious'], 
            "harmless": stats['harmless'],
            "country": country,
            "owner": owner
        }
    else:
        return {"success": False, "error": response.status_code}


# STREAMLIT UI DESIGN
st.title("🛡️ Automated SOC Report Generator")
st.markdown("Enter a suspicious IP address to scan it via Threat Intelligence and generate a PDF report.")

# Search Bar
ip_input = st.text_input("Target IP Address (e.g., 8.8.8.8):")

# Scan Button
if st.button("Start Scan 🚀"):
    if ip_input: 
        with st.spinner('Querying VirusTotal Database...'):
            
            result = check_virustotal(ip_input)
            
            if result["success"]:
                st.success("Analysis Complete!")
                
                col1, col2 = st.columns(2)
                col1.metric("Malicious Flags", result["malicious"])
                col2.metric("Safe Flags", result["harmless"])
                
                st.write(f"**Network Owner:** {result['owner']} | **Country:** {result['country']}")
                
                if result["malicious"] > 0:
                    st.error("🚨 CRITICAL WARNING: Malware or Suspicious Activity Detected!")
                else:
                    st.info("✅ ALL CLEAR: No threats detected for this IP.")
                
                pdf_file = generate_pdf(ip_input, result["malicious"], result["harmless"], result["country"], result["owner"])
                
                with open(pdf_file, "rb") as file:
                    st.download_button(
                        label="📄 Download Advanced Forensic Report",
                        data=file,
                        file_name=pdf_file,
                        mime="application/pdf"
                    )
            else:
                st.error(f"API Error! Status Code: {result['error']}")
    else:
        st.warning("Please enter an IP address first.")