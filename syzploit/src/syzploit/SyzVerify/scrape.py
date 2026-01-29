from typing import Optional
from datetime import datetime
import time

from bs4 import BeautifulSoup, Tag
import requests

from .bug_db import BugMetadata, SyzkallBugDatabase

def get_tag_string(tag: Tag) -> str:
    return ' '.join(tag.find_all(string=True)).strip()

def parse_table_row(row: Tag, header=False) -> list[Tag]:
    assert row.name == 'tr'
    look_tag = 'th' if header else 'td'
    return row.find_all(look_tag)

def parse_table_row_strings(row: Tag, header=False) -> list[str]:
    return [get_tag_string(entry.find(name=True)) for entry in parse_table_row(row, header)]

def parse_table(table: Tag) -> list[dict[str, Tag]]:
    assert table.name == 'table'
    header_values = ['_'.join(value.lower().split()) for value in parse_table_row_strings(table.thead.tr, header=True)]
    
    output = []
    for row in table.tbody.find_all(name='tr'):
        row = parse_table_row(row)
        row_data = {}

        for header, row_value in zip(header_values, row):
            row_data[header] = row_value
        
        output.append(row_data)
            
    return output

# find a table based on if the name in the name in the caption element contains `name_part`
def find_table_by_name(html: BeautifulSoup, name_part: str) -> Tag:
    for caption in html.find_all('caption'):
        if name_part.lower() in get_tag_string(caption).lower():
            parent = caption.parent
            if parent.name == 'table':
                return parent

    return None

def path_to_syzkall_url(url_path: str) -> str:
    return f'https://syzkaller.appspot.com/{url_path}'

def get_syzkall_html(url_path: str) -> BeautifulSoup:
    response = requests.get(path_to_syzkall_url(url_path))
    return BeautifulSoup(response.text, 'html.parser')

def is_memory_unsafety_bug(title: str) -> bool:
    """Return True if the bug title indicates memory unsafety, False otherwise."""
    title = title.lower()

    memory_tags = [
        "kasan", "use-after-free", "out-of-bounds", "slab-out-of-bounds", "heap-buffer-overflow",
        "stack-buffer-overflow", "wild memory access", "invalid-free", "memory corruption",
        "dangling pointer", "null dereference", "use after scope", "double free", "buffer overflow",
        "general protection fault", "KASAN", "UBSAN", "KMSAN", "memory leak", "memory safety"
    ]

    deadlock_tags = [
        "deadlock", "rcu", "lockdep", "locking", "soft lockup", "mutex",
        "rcu stall", "lockup", "hung", "hang"
    ]

    if any(tag in title for tag in memory_tags) and not any(tag in title for tag in deadlock_tags):
        return True
    return False

# filters for bugs which are potentially exploitable
def filter_bugs(data: list[dict[str, Tag]]) -> list[dict[str, Tag]]:
    # we are only interested in bugs with a reproduction
    data = [row for row in data if (get_tag_string(row['repro']) == 'C' or get_tag_string(row['repro']) == 'syz')]
    
    # look for bugs that look exploitable
    data = [row for row in data if is_memory_unsafety_bug(get_tag_string(row['title']))]
    return data

def bug_id_from_url(url_path: str) -> str:
    return url_path.split('=')[1].strip()


def download_bug_by_id(bug_id: str) -> Optional[BugMetadata]:
    """
    Download a single bug directly by its ID from syzbot.
    
    This fetches the bug page directly without needing to scrape the full bug list.
    
    Args:
        bug_id: The syzbot bug ID (e.g., '283ce5a46486d6acdbaf')
    
    Returns:
        BugMetadata if successful, None otherwise
    """
    try:
        # Construct the direct bug URL
        bug_url = f"bug?extid={bug_id}"
        bug_page = get_syzkall_html(bug_url)
        
        # Check if bug exists (look for error message or valid content)
        if bug_page.find(string=lambda text: text and 'not found' in text.lower()):
            print(f"Bug {bug_id} not found on syzbot")
            return None
        
        # Get the bug title from the page
        title_elem = bug_page.find('b')
        if title_elem is None:
            print(f"Could not find title for bug {bug_id}")
            return None
        title = get_tag_string(title_elem).replace('\n', ' ')
        
        # Extract subsystems from title spans
        subsystems = []
        if title_elem.parent:
            subsystems = [get_tag_string(span) for span in title_elem.parent.find_all(name='span', attrs={'class': 'bug-label'})]
        
        # Find crashes table
        crashes_table = find_table_by_name(bug_page, 'crashes')
        if crashes_table is None:
            print(f"No crashes table found for bug {bug_id}")
            return None
        
        table = parse_table(crashes_table)
        
        # Look for a crash with C reproducer
        for c_repro_row in table:
            if get_tag_string(c_repro_row['c_repro']) != 'C':
                continue
            
            # Get assets
            assets = c_repro_row['assets']
            
            disk_image_str = assets.find(string='disk image')
            disk_image_non_bootable = assets.find(string='disk image (non-bootable)')
            
            disk_image_is_bootable = True
            if disk_image_str is None and disk_image_non_bootable is not None:
                disk_image_str = disk_image_non_bootable
                disk_image_is_bootable = False
            
            vmlinux_str = assets.find(string='vmlinux')
            kernel_image_str = assets.find(string='kernel image')
            
            disk_image_path = None if disk_image_str is None else disk_image_str.parent['href']
            vmlinux_path = None if vmlinux_str is None else vmlinux_str.parent['href']
            kernel_image_path = None if kernel_image_str is None else kernel_image_str.parent['href']
            
            # Get syz repro
            syz_repro_a = c_repro_row['syz_repro'].find(name='a', string='syz')
            if syz_repro_a is None:
                continue
            
            c_repro_path = path_to_syzkall_url(c_repro_row['c_repro'].a['href'])
            
            # Kernel commit URL
            kernel_commit_a = c_repro_row['commit'].a
            kernel_commit_url = None if kernel_commit_a is None else kernel_commit_a['href']
            
            # Kernel config URL
            kernel_config_a = c_repro_row['config'].a
            kernel_config_url = None if kernel_config_a is None else path_to_syzkall_url(kernel_config_a['href'])
            
            # Get crash report from page
            crash_report = get_tag_string(bug_page.pre) if bug_page.pre else ""
            
            # Parse crash time
            crash_time_string = get_tag_string(c_repro_row['time'])
            try:
                crash_time = datetime.strptime(crash_time_string, '%Y/%m/%d %H:%M')
            except ValueError:
                crash_time = datetime.now()
            
            return BugMetadata(
                bug_id=bug_id,
                title=title,
                description=get_tag_string(c_repro_row['title']),
                subsystems=subsystems,
                crash_time=crash_time,
                kernel_name=get_tag_string(c_repro_row['kernel']),
                kernel_url=kernel_commit_url,
                kernel_config_url=kernel_config_url,
                crash_report=crash_report,
                syz_repro_url=path_to_syzkall_url(syz_repro_a['href']),
                c_repro_url=c_repro_path,
                disk_image_url=disk_image_path,
                disk_image_is_bootable=disk_image_is_bootable,
                kernel_image_url=kernel_image_path,
                vmlinux_url=vmlinux_path,
            )
        
        # No C repro found, try with syz repro
        for syz_repro_row in table:
            syz_repro_a = syz_repro_row['syz_repro'].find(name='a', string='syz')
            if syz_repro_a is None:
                continue
            
            assets = syz_repro_row['assets']
            
            disk_image_str = assets.find(string='disk image')
            disk_image_non_bootable = assets.find(string='disk image (non-bootable)')
            
            disk_image_is_bootable = True
            if disk_image_str is None and disk_image_non_bootable is not None:
                disk_image_str = disk_image_non_bootable
                disk_image_is_bootable = False
            
            vmlinux_str = assets.find(string='vmlinux')
            kernel_image_str = assets.find(string='kernel image')
            
            disk_image_path = None if disk_image_str is None else disk_image_str.parent['href']
            vmlinux_path = None if vmlinux_str is None else vmlinux_str.parent['href']
            kernel_image_path = None if kernel_image_str is None else kernel_image_str.parent['href']
            
            # C repro URL (may not exist)
            c_repro_url = None
            if syz_repro_row['c_repro'].a:
                c_repro_url = path_to_syzkall_url(syz_repro_row['c_repro'].a['href'])
            
            kernel_commit_a = syz_repro_row['commit'].a
            kernel_commit_url = None if kernel_commit_a is None else kernel_commit_a['href']
            
            kernel_config_a = syz_repro_row['config'].a
            kernel_config_url = None if kernel_config_a is None else path_to_syzkall_url(kernel_config_a['href'])
            
            crash_report = get_tag_string(bug_page.pre) if bug_page.pre else ""
            
            crash_time_string = get_tag_string(syz_repro_row['time'])
            try:
                crash_time = datetime.strptime(crash_time_string, '%Y/%m/%d %H:%M')
            except ValueError:
                crash_time = datetime.now()
            
            return BugMetadata(
                bug_id=bug_id,
                title=title,
                description=get_tag_string(syz_repro_row['title']),
                subsystems=subsystems,
                crash_time=crash_time,
                kernel_name=get_tag_string(syz_repro_row['kernel']),
                kernel_url=kernel_commit_url,
                kernel_config_url=kernel_config_url,
                crash_report=crash_report,
                syz_repro_url=path_to_syzkall_url(syz_repro_a['href']),
                c_repro_url=c_repro_url,
                disk_image_url=disk_image_path,
                disk_image_is_bootable=disk_image_is_bootable,
                kernel_image_url=kernel_image_path,
                vmlinux_url=vmlinux_path,
            )
        
        print(f"No reproducer found for bug {bug_id}")
        return None
        
    except Exception as e:
        import traceback
        print(f"Error downloading bug {bug_id}: {e}")
        traceback.print_exc()
        return None


def pull_single_bug(db: SyzkallBugDatabase, bug_id: str, force: bool = False) -> Optional[BugMetadata]:
    """
    Pull a single bug by ID and save to database.
    
    Args:
        db: The bug database
        bug_id: The syzbot bug ID
        force: If True, re-download even if already in database
    
    Returns:
        BugMetadata if successful, None otherwise
    """
    # Check if already exists
    existing = db.get_bug_metadata(bug_id)
    if existing is not None and not force:
        print(f"Bug {bug_id} already in database (use force=True to re-download)")
        return existing
    
    print(f"Pulling bug {bug_id} from syzbot...")
    metadata = download_bug_by_id(bug_id)
    
    if metadata is None:
        print(f"Failed to download bug {bug_id}")
        return None
    
    db.save_bug_metadata(metadata)
    print(f"Successfully saved bug {bug_id}: {metadata.title}")
    return metadata


def download_bug_metadata(bug: dict[str, Tag]) -> Optional[BugMetadata]:
    try:
        url = bug['title'].a['href']
        bug_page = get_syzkall_html(url)
        crashes_table = find_table_by_name(bug_page, 'crashes')
        
        if crashes_table is None:
            print(f"No crashes table found for bug: {get_tag_string(bug['title']).replace(chr(10), ' ')}")
            return None
        
        table = parse_table(crashes_table)
        
        # Collect all crash reports first
        crash_reports = []
        
        for crash_row in table:
            try:
                assets = crash_row['assets']
                crash_report = {
                    'time': get_tag_string(crash_row['time']),
                    'kernel': get_tag_string(crash_row['kernel']),
                    'commit': get_tag_string(crash_row['commit']),
                    'title': get_tag_string(crash_row['title']),
                    'report_url': crash_row['report'].a['href'] if crash_row['report'].a else None,
                    'syz_repro': crash_row['syz_repro'].find(name='a', string='syz')['href'] if crash_row['syz_repro'].find(name='a', string='syz') else None,
                    'c_repro': crash_row['c_repro'].a['href'] if crash_row['c_repro'].a else None,
                    'console_log': crash_row['log'].a['href'] if crash_row['log'].a else None,
                    'assets': {
                        'disk_image': assets.find(string='disk image').parent['href'] if assets.find(string='disk image') else None,
                        'disk_image_non_bootable': assets.find(string='disk image (non-bootable)').parent['href'] if assets.find(string='disk image (non-bootable)') else None,
                        'vmlinux': assets.find(string='vmlinux').parent['href'] if assets.find(string='vmlinux') else None,
                        'kernel_image': assets.find(string='kernel image').parent['href'] if assets.find(string='kernel image') else None
                    }
                }
                crash_reports.append(crash_report)
            except Exception as e:
                print(f"Error processing crash row: {e}")
                continue

        # Now find the best report to use as primary (prefer one with C repro)
        primary_report = None
        for c_repro_row in table:
            if get_tag_string(c_repro_row['c_repro']) != 'C':
                continue

            # asset paths are full url to google cloud bucket, not relative path like c_repro_path
            assets = c_repro_row['assets']

            disk_image_str = assets.find(string='disk image')
            disk_image_non_bootable = assets.find(string='disk image (non-bootable)')

            # use non bootable image if bootable one does not exist
            disk_image_is_bootable = True
            if disk_image_str is None and disk_image_non_bootable is not None:
                disk_image_str = disk_image_non_bootable
                disk_image_is_bootable = False

            vmlinux_str = assets.find(string='vmlinux')
            kernel_image_str = assets.find(string='kernel image')

            # assets are missing on older bug reports
            disk_image_path = None if disk_image_str is None else disk_image_str.parent['href']
            vmlinux_path = None if vmlinux_str is None else vmlinux_str.parent['href']
            kernel_image_path = None if kernel_image_str is None else kernel_image_str.parent['href']
            
            # title contains subsystems, without false positives
            subsystems = [get_tag_string(span) for span in bug['title'].find_all(name='span', attrs={'class': 'bug-label'})]

            syz_repro_a = c_repro_row['syz_repro'].find(name='a', string='syz')
            if syz_repro_a is None:
                continue

            c_repro_path = path_to_syzkall_url(c_repro_row['c_repro'].a['href'])

            # very rarely kernel commit is not an anchor and doesn't have url, so ignore
            kernel_commit_a = c_repro_row['commit'].a
            kernel_commit_url = None if kernel_commit_a is None else kernel_commit_a['href']

            # also check if config isn't proper link
            kernel_config_a = c_repro_row['config'].a
            kernel_config_url = None if kernel_config_a is None else path_to_syzkall_url(kernel_config_a['href'])

            crash_report = get_tag_string(bug_page.pre)

            crash_time_string = get_tag_string(c_repro_row['time'])
            crash_time = datetime.strptime(crash_time_string, '%Y/%m/%d %H:%M')

            return BugMetadata(
                bug_id=bug_id_from_url(url),
                title=get_tag_string(bug['title']).replace('\n', ' '),
                description=get_tag_string(c_repro_row['title']),
                subsystems=subsystems,
                crash_time=crash_time,
                kernel_name=get_tag_string(c_repro_row['kernel']),
                kernel_url=kernel_commit_url,
                kernel_config_url=kernel_config_url,
                crash_report=crash_report,
                syz_repro_url=path_to_syzkall_url(syz_repro_a['href']),
                c_repro_url=c_repro_path,
                disk_image_url=disk_image_path,
                disk_image_is_bootable=disk_image_is_bootable,
                kernel_image_url=kernel_image_path,
                vmlinux_url=vmlinux_path,
            )
        
        # No suitable crash with C repro found
        print(f"No crash with C repro found for bug: {get_tag_string(bug['title']).replace(chr(10), ' ')}")
        return None
    except Exception as e:
        import traceback
        print(f"Error processing bug {get_tag_string(bug['title']).replace(chr(10), ' ')}: {e}")
        traceback.print_exc()
    return None

# kernel_name is upstream for default linux
# can also be android
def get_bugs_for_kernel(kernel_name: str) -> tuple[list[dict[str, Tag]], list[dict[str, Tag]]]:
    open_bugs_table = find_table_by_name(get_syzkall_html(kernel_name), 'open')
    fixed_bugs_table = get_syzkall_html(f'{kernel_name}/fixed').find_all(name='table')[1]

    bugs_open = filter_bugs(parse_table(open_bugs_table)) if open_bugs_table else []
    bugs_fixed = filter_bugs(parse_table(fixed_bugs_table)) if fixed_bugs_table else []

    return bugs_open, bugs_fixed

def pull_bugs(db: SyzkallBugDatabase, kernel_name: str):
    bugs_open, bugs_fixed = get_bugs_for_kernel(kernel_name)
    bugs_combined = bugs_open + bugs_fixed

    for bug in bugs_combined:
        print('Pulling:')
        print(get_tag_string(bug['title']).replace('\n', ' '))

        url = bug['title'].a['href']
        id = bug_id_from_url(url)
        if db.get_bug_metadata(id) is not None:
            print('already downloaded')
            continue

        bug_metadata = download_bug_metadata(bug)
        time.sleep(5)
        if bug_metadata is None:
            print('Failed to parse')
            continue
        db.save_bug_metadata(bug_metadata)
    print('Downloaded')
    print(f'Have {len(bugs_combined)} bugs in database')