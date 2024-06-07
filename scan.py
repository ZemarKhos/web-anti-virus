import clamd
import yara

def load_yara_rules():
    rules = yara.compile(filepath='yara_rules/sample_rule.yar')
    return rules

def scan_with_virustotal(filepath):
    import requests
    api_key = 'your_virustotal_api_key'
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (filepath, open(filepath, 'rb'))}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response.json()

def scan_file(filepath):
    cd = clamd.ClamdUnixSocket()
    yara_rules = load_yara_rules()
    
    try:
        clamav_result = cd.scan(filepath)
        yara_result = yara_rules.match(filepath)
        virustotal_result = scan_with_virustotal(filepath)
        
        if clamav_result[filepath][0] == 'FOUND':
            return f'Malware found by ClamAV: {clamav_result[filepath][1]}'
        elif yara_result:
            return f'Malware found by YARA: {yara_result}'
        elif virustotal_result.get('positives', 0) > 0:
            return f'Malware found by VirusTotal: {virustotal_result["positives"]} positives'
        else:
            return 'No threats detected'
    except Exception as e:
        return f'Error scanning file: {str(e)}'
