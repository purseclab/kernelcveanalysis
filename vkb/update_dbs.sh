#!/bin/bash

(
cd..

python3 ./create_db.py vulnerabilities.db
python3 ./create_db.py --skip_pocs vulnerabilities_nopocs.db

scp vulnerabilities.db data.cs.purdue.edu:/homes/antoniob/.www/shared/
)

