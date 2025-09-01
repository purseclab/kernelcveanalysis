#!/usr/bin/env python


import sqlite3
import re
import os
import sys



conn = sqlite3.connect(sys.argv[1])
c = conn.cursor()

vuln_id = int(sys.argv[2])
folder = sys.argv[3]
for root, _, files in os.walk(folder):
    for f in files:
        full_path = os.path.join(root, f)
        rel_path = os.path.relpath(full_path, os.path.split(folder)[0])
        with open(full_path, 'rb') as file:
            print(file)
            content = file.read()
            c.execute('''INSERT INTO poc_files (vuln_id, path, content) VALUES (?, ?, ?)''', (vuln_id, rel_path, content))

conn.commit()

