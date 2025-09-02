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
    Moderate = 'Moderate'
    Low = 'Low'

class BugCategory(StrEnum):
    AndroidRuntime = 'Android Runtime'
    Framework = 'Framework'
    MediaFramework = 'Media framework'
    System = 'System'
    Kernel = 'Kernel'
    KernelLts = 'Kernel LTS'

    def is_kernel(self) -> bool:
        return self == BugCategory.Kernel or self == BugCategory.KernelLts

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
        cur.executemany("""
            INSERT OR REPLACE INTO advisories (cve, reference, reference_url, bug_type, severity, category, component, updated_versions, bulletin)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sql_input)
        
        self.commit()
    
    def get_bugs(self) -> list[Bug]:
        cur = self.cursor()
        cur.execute("SELECT id, cve, reference, reference_url, bug_type, severity, category, component, updated_versions, bulletin FROM advisories ORDER BY component")
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


def classify_bug_component(patch_url: str) -> str:
    path_parts = patch_url.split('/')[3:-2]
    path = '/'.join(path_parts)

    components = {
        'platform/packages/modules/Bluetooth': 'bluetooth',
        # old bluetooth repo
        'platform/system/bt': 'bluetooth',
        'platform/packages/modules/Wifi': 'wifi',
        # userspace libraries for networking cell data and other stuff like dhcp
        'platform/packages/modules/Connectivity': 'android_networking',
        # old android networking path
        'platform/frameworks/libs/net': 'android_networking',
        # permission server and ui and managing app permissions
        'platform/packages/modules/Permission': 'permissions',
        # handles which apps should be used for which intents, and shows ui to pick if 2 things are available
        'platform/packages/modules/IntentResolver': 'IntentResolver',
        # statistics and telemetry about ths system
        'platform/packages/modules/StatsD': 'StatsD',
        'platform/packages/modules/HealthFitness': 'HealthFitness',
        # cryptography implementation of hal, hardware assisted keygen and cryptography
        'platform/system/keymint': 'hal_crypto',
        # manages calls, accepting them, voip, etc.
        'platform/packages/services/Telecomm': 'telecomm',
        'platform/packages/services/Telephony': 'Telephony',
        'platform/packages/apps/Settings': 'Settings',
        # documents ui is like the default android file picker that shows up when an app wants to open a file
        'platform/packages/apps/DocumentsUI': 'DocumentsUI',
        # provisioning for enterprise applications
        'platform/packages/apps/ManagedProvisioning': 'ManagedProvisioning',
        # something involved in downloading files
        # apps ask this service to download files in the background
        'platform/packages/providers/DownloadProvider': 'DownloadProvider',
        # manages photos, videos, stored downloads, and permissions for apps to access them
        'platform/packages/providers/MediaProvider': 'MediaProvider',
        'platform/hardware/st/nfc': 'nfc',
        # adobe image format library
        'platform/external/dng_sdk': 'dng_sdk',
        # for GIF images
        'platform/external/giflib': 'giflib',
        # java cryptography library
        'platform/external/conscrypt': 'conscrypt',
        # 2d drawing library
        'platform/external/skia': 'skia',
        # font format parsing and rendering library
        'platform/external/freetype': 'freetype',
        # core android libraries
        # TODO: be more specific
        'platform/system/core': 'core',
        # java standard library implentation for android
        'platform/libcore': 'java_std',
    }

    return components.get(path, path.split('/')[-1])

def get_bugs_from_table(table: PageElement, bulletin: str, category: BugCategory, is_kernel: bool = False) -> list[Bug]:
    rows = table.find_all("tr")[1:]  # skip header row
    advisories = []

    for row in rows:
        cols = row.find_all("td")
        if len(cols) < 5:
            continue

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
            component = '' if reference_url is None else classify_bug_component(reference_url)
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
        table = get_named_bug_table(soup, str(category))

        if table is not None:
            advisories.extend(get_bugs_from_table(table, bulletin, category, is_kernel=category.is_kernel()))

    # Insert into DB with deduplication
    db.add_bugs(advisories)

    print(f"Processed {len(advisories)} advisories (duplicates skipped).")

    print_bugs(advisories)

def reclassify_bugs(db: Db):
    bugs = db.get_bugs()
    for bug in bugs:
        if not bug.category.is_kernel():
            bug.component = '' if bug.reference_url is None else classify_bug_component(bug.reference_url)
    
    db.add_bugs(bugs)

class FilterSet:
    negative: bool
    filter_set: Optional[set[str]]

    def __init__(self, arg_value: Optional[str]):
        self.negative = False
        if arg_value is None:
            self.filter_set = None
            return

        if arg_value.startswith('!'):
            arg_value = arg_value[1:]
            self.negative = True
        
        self.filter_set = set(arg.lower() for arg in arg_value.split(','))
    
    def contains(self, value: str) -> bool:
        if self.filter_set is None:
            return True
        elif self.negative:
            return value.lower() not in self.filter_set
        else:
            return value.lower() in self.filter_set

def list_advisories(db: Db, args: argparse.Namespace):
    """Print stored advisories from SQLite."""

    categories = FilterSet(args.category)
    components = FilterSet(args.component)
    types = FilterSet(args.type)
    severity = FilterSet(args.severity)

    bugs = []
    for bug in db.get_bugs():
        if (
            not categories.contains(str(bug.category))
            or not components.contains(bug.component)
            or not types.contains(str(bug.bug_type))
            or not severity.contains(str(bug.severity))
        ):
            continue

        bugs.append(bug)
    
    print_bugs(bugs)

def main():
    parser = argparse.ArgumentParser(description="Manage Android advisories database.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # import command
    import_parser = subparsers.add_parser("import", help="Import advisories from a given URL")
    import_parser.add_argument("url", help="URL of the Android advisory page")

    # reaclassify command
    subparsers.add_parser("reclassify", help="Reclassify bugs")

    # list command
    list_parser = subparsers.add_parser("list", help="List advisories in the database")
    list_parser.add_argument("--category", type=str, help="Filter based on bug category")
    list_parser.add_argument("--component", type=str, help="Filter based on bug affected component")
    list_parser.add_argument("--type", type=str, help="Filter based on bug type")
    list_parser.add_argument("--severity", type=str, help="Filter based on bug severity")

    args = parser.parse_args()

    db = Db(DB_NAME)
    db.init_db()

    if args.command == "import":
        import_advisories(db, args.url)
    elif args.command == "reclassify":
        reclassify_bugs(db)
    elif args.command == "list":
        list_advisories(db, args)

    db.close()

if __name__ == "__main__":
    main()
