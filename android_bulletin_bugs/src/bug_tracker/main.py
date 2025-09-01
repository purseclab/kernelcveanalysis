import argparse
import requests
from pathlib import Path
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional

import sqlite3
from bs4 import BeautifulSoup
from bs4.element import PageElement
from rich.console import Console
from rich.table import Table

class BugType(StrEnum):
    Rce = 'RCE'
    ElevationOfPrivilege = 'EoP'
    InformationDisclosure = 'ID'
    DenialOfService = 'DoS'

class BugSeverity(StrEnum):
    Critical = 'Critical'
    High = 'High'
    Medium = 'Medium'
    Low = 'Low'

class BugCategory(StrEnum):
    AndroidRuntime = 'Android Runtime'
    Framework = 'Framework'
    MediaFramework = 'Media framework'
    System = 'System'
    Kernel = 'Kernel'
    KernelLts = 'Kernel LTS'

@dataclass
class Bug:
    id: int
    cve: str
    reference: str
    reference_url: str
    bug_type: BugType
    severity: BugSeverity
    category: BugCategory
    component: str
    # not present for kernel
    updated_versions: Optional[list[str]]
    security_bulletin: str

def readable_bulletin(bulletin: str) -> str:
    months = [
        'January',
        'February',
        'March',
        'April',
        'May',
        'June',
        'July',
        'August',
        'September',
        'October',
        'November',
        'December',
    ]

    year, month = bulletin.split('-')

    return f'{year} {months[int(month) - 1]}'

def print_bugs(bugs: list[Bug]):
    table = Table(title='Android Bugs')

    table.add_column('CVE', style='red')
    table.add_column('Category')
    table.add_column('Affected Component')
    table.add_column('Type')
    table.add_column('Severity')
    table.add_column('Affected Versions')
    table.add_column('Patch Date')
    table.add_column('Patch Link', style='dim blue')

    for bug in bugs:
        table.add_row(
            bug.cve,
            str(bug.category),
            bug.component,
            str(bug.bug_type),
            str(bug.severity),
            '' if bug.updated_versions is None else ' '.join(bug.updated_versions),
            readable_bulletin(bug.security_bulletin),
            bug.reference_url,
        )
    
    console = Console()
    console.print(table)

DB_NAME = "android_advisories.db"

class Db:
    # path: Path
    db: sqlite3.Connection

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)

    def close(self):
        self.db.close()

    def cursor(self) -> sqlite3.Cursor:
        return self.db.cursor()
    
    def commit(self):
        self.db.commit()

    def init_db(self):
        cur = self.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS advisories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve TEXT NOT NULL UNIQUE,
                reference TEXT,
                reference_url TEXT,
                bug_type TEXT,
                severity TEXT,
                category TEXT,
                component TEXT,
                updated_versions TEXT,
                bulletin TEXT
            )
        """)
        self.commit()
    
    def add_bugs(self, bugs: list[Bug]):
        cur = self.cursor()

        sql_input = [
            (bug.cve, bug.reference, bug.reference_url, str(bug.bug_type), str(bug.severity), str(bug.category), bug.component, None if bug.updated_versions is None else ','.join(bug.updated_versions), bug.security_bulletin)
            for bug in bugs
        ]
        print(sql_input)
        cur.executemany("""
            INSERT OR IGNORE INTO advisories (cve, reference, reference_url, bug_type, severity, category, component, updated_versions, bulletin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sql_input)
        
        self.commit()
    
    def get_bugs(self) -> list[Bug]:
        cur = self.cursor()
        cur.execute("SELECT id, cve, reference, reference_url, bug_type, severity, category, component, updated_versions, bulletin FROM advisories ORDER BY cve")
        rows = cur.fetchall()

        return [
            Bug(
                id=row[0],
                cve=row[1],
                reference=row[2],
                reference_url=row[3],
                bug_type=BugType(row[4]),
                severity=BugSeverity(row[5]),
                category=BugCategory(row[6]),
                component=row[7],
                updated_versions=None if row[8] is None else row[8].split(','),
                security_bulletin=row[9],
            ) for row in rows
        ]


def get_bugs_from_table(table: PageElement, bulletin: str, category: BugCategory, is_kernel: bool = False) -> list[Bug]:
    rows = table.find_all("tr")[1:]  # skip header row
    advisories = []

    for row in rows:
        cols = row.find_all("td")
        if len(cols) < 5:
            continue

        print(row)

        cve = cols[0].get_text(strip=True)

        ref_link = cols[1].find("a")
        reference = ref_link.get_text(strip=True) if ref_link else None
        reference_url = ref_link["href"] if ref_link else None

        bug_type = BugType(cols[2].get_text(strip=True))
        severity = BugSeverity(cols[3].get_text(strip=True))
        updated_versions = cols[4].get_text(strip=True).split()
        updated_versions = [
            version.strip(',') for version in updated_versions
        ]

        if is_kernel:
            component = cols[4].get_text(strip=True)
            updated_versions = None
        else:
            component = ''
            updated_versions = cols[4].get_text(strip=True).split()
            updated_versions = [
                version.strip(',') for version in updated_versions
            ]

        bug = Bug(
            id=0,
            cve=cve,
            reference=reference,
            reference_url=reference_url,
            bug_type=bug_type,
            severity=severity,
            category=category,
            component=component,
            updated_versions=updated_versions,
            security_bulletin=bulletin,
        )

        advisories.append(bug)
    
    return advisories

def get_named_bug_table(soup: BeautifulSoup, name: str) -> Optional[PageElement]:
    element = soup.find('h3', attrs={"data-text": name})
    if element is None:
        return None
    
    return element.find_next('table')

def import_advisories(db: Db, bulletin: str):
    """Fetch the advisories page, parse it, and insert entries into SQLite."""

    url = f'https://source.android.com/docs/security/bulletin/{bulletin}-01'

    resp = requests.get(url)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    
    advisories = []

    for category in BugCategory:
        is_kernel = category == BugCategory.Kernel or category == BugCategory.KernelLts
        table = get_named_bug_table(soup, str(category))

        if table is not None:
            advisories.extend(get_bugs_from_table(table, bulletin, category, is_kernel))
    
    print(advisories)

    # Insert into DB with deduplication
    db.add_bugs(advisories)

    print(f"Processed {len(advisories)} advisories (duplicates skipped).")

def list_advisories(db: Db):
    """Print stored advisories from SQLite."""

    print_bugs(db.get_bugs())

def main():
    parser = argparse.ArgumentParser(description="Manage Android advisories database.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # import command
    import_parser = subparsers.add_parser("import", help="Import advisories from a given URL")
    import_parser.add_argument("url", help="URL of the Android advisory page")

    # list command
    subparsers.add_parser("list", help="List advisories in the database")

    args = parser.parse_args()

    db = Db(DB_NAME)
    db.init_db()

    if args.command == "import":
        import_advisories(db, args.url)
    elif args.command == "list":
        list_advisories(db)

    db.close()

if __name__ == "__main__":
    main()
