import wget
import os
import requests
import json


def get_nvd_feed():
    #data from https://nvd.nist.gov/developers/vulnerabilities
    #url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip' # NVD Feed URL
    url='https://services.nvd.nist.gov/rest/json/cves/2.0'
    wget.download(url)
    #command = 'unzip -o nvdcve-1.0-recent.json.zip' # Unzip json.gz file
    #os.system(command)

def get_cpes():
    with open('cpe.txt', 'r') as v:
        cpe = v.readlines()
        return cpe

def parse_nvd_feed(cpes):
    #get_nvd_feed()
    with open('nvdcve-2.0.json','r') as f:
        cve_feed = json.load(f)
    cve_index = 0
    cve_count = 0
    message = ""

    for x in cve_feed['vulnerabilities']:
        id = cve_feed['vulnerabilities'][cve_index]['cve']['id']
        description = cve_feed['vulnerabilities'][cve_index]['cve']['descriptions'][0]['value']
        try:
            #before was cpe_match
            cpe_string = cve_feed['vulnerabilities'][cve_index]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria']
        except:
            cpe_string = ""
        for line in cpes:
            for cpe in line.split():
                #for x in cpe_string:
                if cpe in cpe_string:
                    #print("Desc:", description)
                    #print("CVE ID:", id)
                    #print("CPE: ",cpe)
                    #print("cpe found: ",cpe_string) 
                    message = message + slack_block_format(cpe, description, id)
                    aux=slack_block_formatv2(cpe, description, id)
                    print(aux)
                    send_slack_CVE(aux)
                    cve_count = cve_count + 1
        cve_index = cve_index + 1
    return message,cve_count

def slack_block_format(product, description, id):
    
    block = '{"blocks": [{"type": "section","text": {"type": "plain_text","emoji": true,"text": ""*Product:* ' + product + '\n *CVE ID:* ' + id + '\n *Description:* ' + description + '\n "}}]}'
    #block = ',{"type": "section", "text": {"type": "mrkdwn","text": "*Product:* ' + product + '\n *CVE ID:* ' + id + '\n *Description:* ' + description + '\n "}}, {"type": "divider"}'
    #print("new block: ", block)
    return block

def slack_block_formatv2(product, description, id):
    block = '{"blocks": [{"type": "section","text": {"type": "mrkdwn","text": "*Product:* ' + product + '\n *CVE ID:* ' + id + '\n *Description:* ' + description +' "}}]}'
    return block

def send_slack_CVE(message):
    #change to read from os variable
    url=""
    x = requests.post(url, data=message)

def send_slack_alert(message,cve_count):
    #url = os.getenv('SLACK_WEBHOOK')
    #change to read from os variable
    url=""
    print(url)
    slack_message = '{"blocks": [{"type": "section","text": {"type": "plain_text","emoji": true,"text": "Hello :wave:, we *found* '+ str(cve_count) +' CVEs"}}]}'
    #slack_message ='{"text":"Hello :wave:, we found '+ str(cve_count)+' CVEs"}'
    slack_message2 = '{"blocks": [{"type": "section","text": {"type": "plain_text","emoji": true,"text": "Today '+ message + '"}}]}'
    #slack_message2 =' Security Vulnerabilities affecting your Tech Stack were disclosed today."}}' + message + ']}'
    #slack_message ='{"text":"Hello, World!"}'
    print(slack_message2)
    x = requests.post(url, data=slack_message)
    #x = requests.post(url, data=slack_message2)

def main():
    print("VulnAlerts Using GitHub Actions\n")
    message,cve_count = parse_nvd_feed(get_cpes())
    send_slack_alert(message,cve_count)
    print("Notification Sent")

if __name__ == '__main__':
    main()
