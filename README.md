# Content
This repository contains the results of our research regarding Linux and Android Kernel exploitation.

### Generate the exploit database
```bash
python3 ./create_db.py vulnerabilities.db
```

To run the script a few Python packages are required. You can install them by runnning:
```bash
pip install sqlalchemy
```

To include POCs' code in the database, cloning Google's kernelctf repository is required.
To clone it, run:
```bash
cd ..
git clone git@github.com:google/security-research.git
```

A pre-generated database with no POC code is avaialable in `vulnerabilities_nopocs.db`. 

A pre-generated databse with POCs' code is avaialbe here: [vulnerabilities.db](https://www.cs.purdue.edu/homes/antoniob/shared/vulnerabilities.db).

