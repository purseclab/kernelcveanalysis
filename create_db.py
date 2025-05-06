#!/usr/bin/env python


import sqlite3
import re
import os
import sys


# Define paths
MARKDOWN_FILE = 'exploit_breakdown_notes/exploit breakdown/Exploit Table.md'
REPORTS_DIR = 'exploit_breakdown_notes/exploit breakdown/'
POC_DIR = '../security-research/pocs/linux/kernelctf/'
DATABASE = 'vulnerabilities.db'

MITRE_BASE_URL = 'https://www.cve.org/CVERecord?id='

# Connect to SQLite and create schema
def create_schema():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                 id INTEGER PRIMARY KEY,
                 cve TEXT,
                 full_name TEXT,
                 android_poc BOOL,
                 pocs_link TEXT,
                 exploit_family TEXT,
                 tested_mitigations TEXT,
                 subsystem TEXT,
                 bug_type TEXT,
                 bug_details TEXT,
                 exploit_techniques TEXT,
                 code_execution_method TEXT,
                 privilege_escalation_technique TEXT,
                 kaslr_leak_method TEXT,
                 data_address_leaks TEXT,
                 required_config TEXT,
                 link TEXT
                 )''')

    c.execute('''CREATE TABLE IF NOT EXISTS reports (
                 id INTEGER PRIMARY KEY,
                 vuln_id INTEGER,
                 cve TEXT,
                 full_name TEXT,
                 content TEXT,
                 FOREIGN KEY(vuln_id) REFERENCES vulnerability(id)
                 )''')

    c.execute('''CREATE TABLE IF NOT EXISTS poc_files (
                 id INTEGER PRIMARY KEY,
                 vuln_id INTEGER,
                 path TEXT,
                 content BLOB,
                 FOREIGN KEY(vuln_id) REFERENCES vulnerability(id)
                 )''')

    conn.commit()
    return conn

# Parse markdown table
def parse_markdown():
    with open(MARKDOWN_FILE, 'r') as f:
        lines = f.readlines()

    data_started = False
    vulns = []

    for line in lines:
        if re.match(r'^\|? *-{3,}', line):
            data_started = True
            continue

        if data_started and line.strip().startswith('|'):
            cols = [col.strip() for col in line.strip('|\n').split('|')]

            # Check if there's a link in the exploit column
            exploit_link = None
            exploit_name = cols[0]
            el = ""
            if "http" in exploit_name:
                el = "http"+exploit_name.replace(")","").strip().split("http")[1]

            link_match = re.match(r'\[\[(.*?)\]\]', exploit_name)
            if link_match:
                exploit_name = link_match.group(1)
                if not el:
                    if "http" in el:
                        exploit_link = exploit_name
                    else:
                        exploit_link = MITRE_BASE_URL+exploit_name.split()[0]
                else:
                    exploit_link = el
            else:
                exploit_link = MITRE_BASE_URL+exploit_name.split()[0]

            e2 = exploit_name.replace("Android","").strip()
            for e in e2.split("and"):
                e = e.strip()
                mit = ""
                if "(" in e:
                    mit = e.split("(")[1].split(")")[0]
                    mit = ",".join([m.strip() for m in mit.split(",")])
                e = e.split("(")[0].strip()
                vuln = {
                    'cve': e,
                    'full_name': exploit_name,
                    'android_poc': "Android" in exploit_name,
                    'pocs' : re.findall(r'\[.*?\]\(([^)]+)\)', cols[1]),
                    'exploit_family': cols[2],
                    'tested_mitigations': mit,
                    'subsystem': cols[3],
                    'bug_type': cols[4],
                    'bug_details': cols[5],
                    'exploit_techniques': cols[6],
                    'code_execution_method': cols[7],
                    'privilege_escalation_technique': cols[8],
                    'kaslr_leak_method': cols[9],
                    'data_address_leaks': cols[10],
                    'required_config': cols[11],
                    'link': exploit_link
                }
                vulns.append(vuln)

    return vulns

# Insert data into the database
def populate_db(conn, vulns, add_pocs=True):
    c = conn.cursor()

    for vuln in vulns:
        c.execute('''INSERT OR IGNORE INTO vulnerabilities (cve, full_name, android_poc, pocs_link, 
                    exploit_family, tested_mitigations, subsystem, bug_type, bug_details,
                    exploit_techniques, code_execution_method, privilege_escalation_technique,
                    kaslr_leak_method, data_address_leaks, required_config, link)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (vuln['cve'], vuln['full_name'], vuln['android_poc'],
                   ", ".join(vuln['pocs']), vuln['exploit_family'],
                   vuln['tested_mitigations'], vuln['subsystem'], vuln['bug_type'], vuln['bug_details'],
                   vuln['exploit_techniques'], vuln['code_execution_method'], vuln['privilege_escalation_technique'],
                   vuln['kaslr_leak_method'], vuln['data_address_leaks'], vuln['required_config'], vuln['link']))

        vuln_id = c.lastrowid

        # Insert report content if available
        report_path = os.path.join(REPORTS_DIR, vuln['cve'])
        ldir = [f for f in os.listdir(REPORTS_DIR) if vuln['cve'] in f]
        for f in ldir:
            with open(os.path.join(REPORTS_DIR, f), 'r') as rf:
                report_content = rf.read()
                c.execute('INSERT INTO reports (vuln_id, cve, full_name, content) VALUES (?, ?, ?, ?)',
                          (vuln_id, vuln['cve'], f, report_content))

        if add_pocs:
            # Insert PoC content if available
            for poc in vuln['pocs']:
                if poc.startswith("/"):
                    folder = "."+poc
                else:
                    folder = os.path.join(POC_DIR, os.path.basename(poc))
                print("processing POC", folder)
                for root, _, files in os.walk(folder):
                    for f in files:
                        full_path = os.path.join(root, f)
                        rel_path = os.path.relpath(full_path, os.path.split(folder)[0])
                        with open(full_path, 'rb') as file:
                            content = file.read()
                            c.execute('''INSERT INTO poc_files (vuln_id, path, content) VALUES (?, ?, ?)''',
                                (vuln_id, rel_path, content))

    conn.commit()

# Main function
def main():

    if len(sys.argv)<2:
        print('''Usage:
            python3 ./create_db.py [--skip_pocs] vulnerabilities.db
            ''')
        sys.exit(1)

    global DATABASE
    DATABASE = sys.argv[-1]

    if "--skip_pocs" in sys.argv:
        add_pocs = False
    else:
        if not os.path.exists(POC_DIR):
            print('''To process POCs I need the kernelctf repository cloned in '''+POC_DIR)
            print('''\nTo fix, run:
cd ..
git clone git@github.com:google/security-research.git
                ''')
            sys.exit(1)
        add_pocs = True

    try:
        os.unlink(DATABASE)
    except OSError:
        pass

    conn = create_schema()
    vulns = parse_markdown()
    populate_db(conn, vulns, add_pocs)
    conn.close()

if __name__ == '__main__':
    main()
