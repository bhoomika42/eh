from flask import Flask, render_template, request, jsonify
import whois
import nmap
import subprocess
import os

app = Flask(__name__)
nm = nmap.PortScanner()

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/contact')
def contactus():
    return render_template('contact.html')
    
@app.route('/passive_recon')
def passive_recong():
    return render_template('passive_recon.html')

@app.route('/active_recon')
def active_recong():
    return render_template('active_recon.html')

@app.route('/openvas')
def openvas_page():
    return render_template('openvas.html')

@app.route('/dirbuster')
def dirbuster_page():
    return render_template('dirbuster.html')
    
@app.route('/sqlmap')
def sqlmap_page():
    return render_template('sqlmap.html')
    
@app.route('/whois', methods=['POST'])
def whois_lookup():
    domain = request.json.get('domain')
    try:
        domain_info = whois.whois(domain)
        # Convert all the information into a dictionary format to send as a response
        result = {
            'domain_name': domain_info.domain_name,
            'registrar': domain_info.registrar,
            'creation_date': str(domain_info.creation_date),
            'expiration_date': str(domain_info.expiration_date),
            'updated_date': str(domain_info.updated_date),
            'status': domain_info.status,
            'name_servers': domain_info.name_servers,
            'emails': domain_info.emails,
            'dnssec': domain_info.dnssec,
            'whois_server': domain_info.whois_server,
            'org': domain_info.org,
            'country': domain_info.country,
            'state': domain_info.state,
            'city': domain_info.city,
            'address': domain_info.address,
            'zipcode': domain_info.zipcode,
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/nmap_scan', methods=['POST'])
def nmap_scan():
    target = request.json.get('target')
    try:
        # Scan the target using Nmap
        scan_result = nm.scan(target, arguments='-sV')
        result = {
            'host': target,
            'state': scan_result['scan'][target]['status']['state'],
            'protocols': []
        }
        # Iterate over all protocols and ports
        for proto in scan_result['scan'][target].keys():
            if proto in ['tcp', 'udp']:
                ports = scan_result['scan'][target][proto].keys()
                for port in ports:
                    port_info = scan_result['scan'][target][proto][port]
                    result['protocols'].append({
                        'protocol': proto,
                        'port': port,
                        'state': port_info['state'],
                        'name': port_info['name'],
                        'product': port_info.get('product', 'N/A'),
                        'version': port_info.get('version', 'N/A')
                    })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/dirbuster_scan', methods=['POST'])
def dirbuster_scan():
    target = request.json.get('target')
    try:
        # Run DirBuster (dirsearch) command with --quiet to suppress unnecessary output
        command = ['python3', 'dirsearch/dirsearch.py', '-u', target, '-e', 'php,html', '--quiet']
        result = subprocess.run(command, capture_output=True, text=True)

        # If the command completed successfully, return the result
        if result.returncode == 0:
            return jsonify({'output': result.stdout})
        else:
            return jsonify({'error': 'An error occurred during the scan', 'details': result.stderr})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
        
@app.route('/sqlmap_scan', methods=['POST'])
def sqlmap_scan():
    target = request.json.get('target')
    try:
        # Run SQLMap command
        command = ['python3', 'sqlmap-dev/sqlmap.py', '-u', target, '--batch']
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({'output': result.stdout})
        else:
            return jsonify({'error': 'An error occurred during the SQLMap scan', 'details': result.stderr})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
