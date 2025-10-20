from typing import NewType, TypeVar, Callable, Self, Optional
from pathlib import Path
from tempfile import NamedTemporaryFile
from dataclasses import dataclass
from collections import defaultdict
from itertools import chain
from enum import StrEnum
import subprocess
import itertools

from .adb import read_file, run_adb_command, runas, Permissions, upload_tools
from .util import config_lines
from .codeql import CodeqlQuery, CodeqlContext

T = TypeVar('T')

# possible locations of selinux policy
# obtained from `strace restorecon /data/local/tmp &>&1 | grep open`
#
# openat(AT_FDCWD, "/system/etc/selinux/plat_file_contexts", O_RDONLY|O_CLOEXEC) = 3
# openat(AT_FDCWD, "/system_ext/etc/selinux/system_ext_file_contexts", O_RDONLY|O_CLOEXEC) = 3
# openat(AT_FDCWD, "/product/etc/selinux/product_file_contexts", O_RDONLY|O_CLOEXEC) = 3
# openat(AT_FDCWD, "/vendor/etc/selinux/vendor_file_contexts", O_RDONLY|O_CLOEXEC) = 3
#
# Most of the policies are in the first one, but the others do have some

SELINUX_APP_CONTEXTS = 'seapp_contexts'
SELINUX_SERVICE_CONTEXTS = 'service_contexts'
SELINUX_HWSERVICE_CONTEXTS = 'hwservice_contexts'
SELINUX_FILE_CONTEXTS = 'file_contexts'

SELINUX_CONFIG_PREFIXES = [
    '/system/etc/selinux/plat_',
    '/system_ext/etc/selinux/system_ext_',
    '/product/etc/selinux/product_',
    '/vendor/etc/selinux/vendor_',
]

def read_selinux_configs(config_name: str) -> str:
    '''
    Reads a certain type of selinux config from all the different places it can be defined on the system,
    and concatenates the output together.
    '''

    return '\n'.join(
        read_file(prefix + config_name).decode('utf-8')
        for prefix in SELINUX_CONFIG_PREFIXES
    )

SeType = NewType('SeType', str)
SeClass = NewType('SeClass', str)

@dataclass
class SeLabel:
    user: str
    role: str
    type: SeType
    level: str

    @classmethod
    def parse(cls, label: str) -> Self:
        parts = label.split(':')
        assert len(parts) == 4

        return cls(
            user=parts[0],
            role=parts[1],
            type=SeType(parts[2]),
            level=parts[3],
        )

def parse_selinux_map_file(config_name: str) -> dict[str, SeLabel]:
    out = {}

    config = read_selinux_configs(config_name)

    for line in config_lines(config):
        parts = line.split()
        out[''.join(parts[:-1])] = SeLabel.parse(parts[-1])
    
    return out

def inv_selinux_map(map: dict[str, SeLabel]) -> dict[SeType, list[str]]:
    out = defaultdict(list)
    for service, label in map.items():
        out[label.type].append(service)
    
    return dict(out)

class ServiceSelinuxMapping:
    '''
    This class represents all information from `/system/etc/selinux/plat_service_contexts` file.

    So it handles mapping service names to selinux domains.
    '''
    # map from service name to SeLabel
    services: dict[str, SeLabel]
    fallback: SeLabel

    def __init__(self, file: str):
        self.services = parse_selinux_map_file(file)
        self.fallback = self.services['*']
    
    def label_to_service_name_map(self) -> dict[SeType, list[str]]:
        return inv_selinux_map(self.services)
    
    def get_selabel(self, service_name: str) -> SeLabel:
        if service_name in self.services:
            return self.services[service_name]
        else:
            return self.fallback
    
    # doesn't check fallback services
    def services_for_setype(self, setype: SeType) -> list[str]:
        return [service for service, label in self.services.items() if label.type == setype]

class FileSelinuxMapping:
    files: dict[str, SeLabel]

    def __init__(self):
        self.files = parse_selinux_map_file(SELINUX_FILE_CONTEXTS)
    
    def type_to_file_name_map(self) -> dict[SeType, list[str]]:
        return inv_selinux_map(self.files)


@dataclass
class AllowRule:
    source_type: SeType
    dst_type: SeType
    seclass: SeClass
    permissions: list[str]

    @classmethod
    def parse_from_rule(cls, rule: str) -> Self:
        rule = rule.strip()
        if rule.endswith(';'):
            rule = rule[:-1]
        
        parts = rule.split()
        assert parts[0] == 'allow'

        if '{' in rule:
            permissions = rule.split('{')[1].split('}')[0].split()
        else:
            permissions = [parts[3]]

        
        return cls(
            source_type=SeType(parts[1]),
            dst_type=SeType(parts[2].split(':')[0]),
            seclass=SeClass(parts[2].split(':')[1]),
            permissions=permissions,
        )
    
    # use for sesearch output for example
    @classmethod
    def parse_many_rules(cls, rules: str) -> list[Self]:
        return [
            cls.parse_from_rule(line.strip())
            for line in rules.split('\n') if line.strip() != ''
        ]

@dataclass
class SeAttribute:
    name: str
    types: set[str]

class SePolicy:
    policy: bytes
    attributes: dict[str, SeAttribute]

    def __init__(self):
        self.policy = read_file('/sys/fs/selinux/policy')
        self.attributes = self.collect_attributes()

    def with_policy_file(self, callback: Callable[[Path], T]) -> T:
        with NamedTemporaryFile() as f:
            f.write(self.policy)
            f.flush()
            return callback(Path(f.name))
    
    def run_setools_command(self, command: str, args: list[str]) -> str:
        def run_command(file: Path) -> str:
            search_args = [command, str(file)]
            search_args.extend(args)

            return subprocess.run(
                search_args,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        
        return self.with_policy_file(run_command)

    def seinfo(self, args: list[str]) -> str:
        return self.run_setools_command('seinfo', args)

    def sesearch(self, args: list[str]) -> str:
        return self.run_setools_command('sesearch', args)
    
    def search_rules(self, args: list[str]) -> list[AllowRule]:
        output = self.sesearch(args)
        return AllowRule.parse_many_rules(output)
    
    def collect_attributes(self) -> dict[str, SeAttribute]:
        out = {}

        output = self.seinfo(['-a', '-x']).strip()
        parts = output.split('attribute')[1:]

        for part in parts:
            lines = part.strip().splitlines()

            attribute_name = lines[0].split(';')[0].strip()
            types = set(type.strip() for type in lines[1:] if len(type.strip()) > 0)
            if '<empty attribute>' in types:
                types = set()
            
            out[attribute_name] = SeAttribute(
                name=attribute_name,
                types=types,
            )
        
        return out
    
    def types_in_attribute(self, attribute: str) -> Optional[set[str]]:
        if attribute in self.attributes:
            return self.attributes[attribute].types
        else:
            return None
    
    def expand_rule_attributes(self, rules: list[AllowRule]) -> list[AllowRule]:
        out = []
        for rule in rules:
            source_types = self.types_in_attribute(rule.source_type)
            if source_types is None:
                source_types = {rule.source_type}
            
            dst_types = self.types_in_attribute(rule.dst_type)
            if dst_types is None:
                dst_types = {rule.dst_type}
            
            out.extend(AllowRule(
                source_type=source_type,
                dst_type=dst_type,
                seclass=rule.seclass,
                permissions=rule.permissions,
            ) for source_type, dst_type in itertools.product(source_types, dst_types))
        
        return out

    def rules_for_permission(self, clazz: str, permission: str) -> list[AllowRule]:
        return self.search_rules([
            '--allow',
            # search for service manager class
            '-c', clazz,
            # for rules with find permission
            '-p', permission,
        ])

@dataclass
class FileInfo:
    file_regex: str
    exact_match: bool
    permissions: set[str]

    def __repr__(self) -> str:
        if self.exact_match:
            return f'{self.file_regex} (exact): {self.permissions}'
        else:
            return f'{self.file_regex}: {self.permissions}'

@dataclass
class ServiceInfo:
    service_name: str
    service_interface: str

def get_services_for_permissions(permissions: Permissions) -> list[ServiceInfo]:
    out = []

    for line in runas('service list', permissions).splitlines():
        parts = line.split()

        # skip first line
        if not parts[0].isdigit():
            continue

        # skip : at end
        service_name = parts[1][:-1]
        # skip []
        service_interface = parts[2][1:-1]
        if len(service_interface.split(',')) > 1:
            print('Warning: unimplemented support for multiple interfaces')
            print(line)
        
        # skip services we cannot access
        if len(service_interface) == 0:
            continue

        out.append(ServiceInfo(
            service_name=service_name,
            service_interface=service_interface,
        ))
    
    return out


@dataclass
class AccessibleServices:
    allowlist: list[ServiceInfo]
    # if None, only allowed services are allowlist
    # if not None, all other services other then these are allowed
    blocklist: Optional[list[ServiceInfo]]

class ServiceType(StrEnum):
    SERVICE = 'service'
    HW_SERVICE = 'hwservice'

class ServiceContext:
    '''
    Represents info about particular services on a binder instance.

    Either reguler services or hwservices.
    '''

    # mapping from type to service types it can access
    accessible_service_map: dict[SeType, list[SeType]]

    service_labels: ServiceSelinuxMapping

    def __init__(self, service_type: ServiceType, policy: SePolicy):
        match service_type:
            case ServiceType.SERVICE:
                self.accessible_service_map = self.compute_accessible_service_map(policy, 'service_manager', 'find')
                self.service_labels = ServiceSelinuxMapping(SELINUX_SERVICE_CONTEXTS)
            case ServiceType.HW_SERVICE:
                self.accessible_service_map = self.compute_accessible_service_map(policy, 'hwservice_manager', 'find')
                self.service_labels = ServiceSelinuxMapping(SELINUX_HWSERVICE_CONTEXTS)
    
    # compute mapping which indicates which objects a process with a given context can access
    @classmethod
    def compute_accessible_service_map(cls, policy: SePolicy, clazz: str, permision: str) -> dict[SeType, list[SeType]]:
        accessible_service_map = defaultdict(list)

        # relevant code: https://cs.android.com/android/platform/superproject/main/+/main:system/hwservicemanager/AccessControl.cpp
        rules = policy.rules_for_permission(clazz, permision)
        for rule in policy.expand_rule_attributes(rules):
            accessible_service_map[rule.source_type].append(rule.dst_type)

        return dict(accessible_service_map)

class SelinuxContext:
    policy: SePolicy
    services: dict[ServiceType, ServiceContext]
    # mapping from service name to service info
    service_interfaces: dict[str, ServiceInfo]

    # mapping from type to files with that selinux type
    file_label_map: dict[SeType, list[str]]

    def __init__(self):
        self.policy = SePolicy()
        self.services = { service_type: ServiceContext(service_type, self.policy) for service_type in ServiceType }

        self.service_interfaces = {}
        for service in get_services_for_permissions(Permissions.root()):
            self.service_interfaces[service.service_name] = service
        
        self.file_label_map = FileSelinuxMapping().type_to_file_name_map()

    def service_names_to_service_info(self, service_names: list[str], service_type: ServiceType = ServiceType.SERVICE) -> list[ServiceInfo]:
        if service_type == ServiceType.SERVICE:
            # regular services are listed in `plat_service_contexts` exactly as named on system
            return [
                self.service_interfaces[service] for service in service_names
                if service in self.service_interfaces
            ]
        elif service_type == ServiceType.HW_SERVICE:
            # hw services have a slightly weird syntax
            # they are written in `plat_hwservice_contexts` as package.name::IInterfaceName
            # and that will match things like `package.name.IInterfaceName/extra_info`

            def to_hwservice_name(service_name: str) -> str:
                parts = service_name.split('/')[0].split('.')
                return '.'.join(parts[:-1]) + '::' + parts[-1]
            
            service_names_set = set(service_names)

            return [
                service_info for service_info in self.service_interfaces.values()
                if to_hwservice_name(service_info.service_name) in service_names_set
            ]
    
    def accesible_services_for_domain(self, domain_type: SeType, service_type: ServiceType = ServiceType.SERVICE) -> AccessibleServices:
        service_context = self.services[service_type]

        can_access_fallback = False

        # check if no services are accessible
        if domain_type not in service_context.accessible_service_map:
            return AccessibleServices(
                allowlist=[],
                blocklist=None,
            )

        accesible_services = service_context.accessible_service_map[domain_type]
        can_access_fallback = service_context.service_labels.fallback.type in accesible_services

        service_names = []
        for type in accesible_services:
            service_names.extend(service_context.service_labels.services_for_setype(type))
        
        forbidden_services = None
        if can_access_fallback:
            all_services = service_context.service_labels.label_to_service_name_map()
            for type in accesible_services:
                if type in all_services:
                    del all_services[type]
            
            forbidden_services = list(chain.from_iterable(all_services.values))
        
        return AccessibleServices(
            allowlist=self.service_names_to_service_info(service_names, service_type=service_type),
            blocklist=None if forbidden_services is None else self.service_names_to_service_info(forbidden_services),
        )
    
    def accesible_files_for_domain(self, domain_type: SeType) -> dict[str, FileInfo]:
        rules = self.policy.search_rules([
            # TODO: use -A and parse allowxperm
            '--allow',
            '-s', str(domain_type),
            '-c', 'file',
        ])

        rules = self.policy.expand_rule_attributes(rules)

        allowed_files = {}

        for rule in rules:
            if rule.dst_type in self.file_label_map:
                for file in self.file_label_map[rule.dst_type]:
                    if file not in allowed_files:

                        exact = False
                        # if file had -- in it, it is exact match
                        if file.endswith('--'):
                            file = file[:-2]
                            exact = True
                        
                        allowed_files[file] = FileInfo(
                            file_regex=file,
                            exact_match=exact,
                            permissions=set()
                        )
                    
                    allowed_files[file].permissions.update(rule.permissions)
        
        return { file: file_info for file, file_info in allowed_files.items() if len(file_info.permissions) > 0}
    
    def print_accesible_files_for_domain(self, domain_type: SeType):
        print('accessible files')
        for file_info in self.accesible_files_for_domain(domain_type).values():
            print(file_info)

    def print_accesible_services(self, domain_type: SeType):
        for service_type in ServiceType:
            services = self.accesible_services_for_domain(domain_type, service_type=service_type)

            print(f'{domain_type} can access {service_type}:')
            for service in services.allowlist:
                print(service)
            
            print(f'Can access fallback: {services.blocklist is not None}')
            if services.blocklist is not None:
                for service in services.blocklist:
                    print(service)
            
            print()
    
    def print_info_for_domain(self, domain_type: SeType):
        self.print_accesible_services(domain_type)
        self.print_accesible_files_for_domain(domain_type)
    
    def diff_accesible_files_for_domain(self, domain1: SeType, domain2: SeType):
        files1 = self.accesible_files_for_domain(domain1)
        files2 = self.accesible_files_for_domain(domain2)

        print(f'differing file permissions between {domain1} and {domain2}')
        print(f'only {domain1} can access:')
        for file, file_info in dict(files1).items():
            if file_info.file_regex not in files2:
                print(file_info)
                del files1[file]
        print()
        
        print(f'only {domain2} can access:')
        for file, file_info in dict(files2).items():
            if file_info.file_regex not in files1:
                print(file_info)
                del files2[file]
        print()
        
        print('different permissions between domains:')
        for file, file_info1 in files1.items():
            file_info2 = files2[file]
            if file_info1.permissions != file_info2.permissions:
                print(f'file `{file}`:')
                print(f'{domain1} permissions: {sorted(file_info1.permissions)}')
                print(f'{domain2} permissions: {sorted(file_info2.permissions)}')
        print()
    
    def diff_accessible_services_for_domain(self, domain1: SeType, domain2: SeType):
        for service_type in ServiceType:
            service_info1 = self.accesible_services_for_domain(domain1, service_type)
            service_info2 = self.accesible_services_for_domain(domain2, service_type)
            # TODO: impement diffing with fallback service
            assert service_info1.blocklist is None and service_info2.blocklist is None, 'unimplemented'

            services1 = { service.service_name: service for service in service_info1.allowlist }
            services2 = { service.service_name: service for service in service_info2.allowlist }

            print(f'differing {service_type} permissions between {domain1} and {domain2}')
            print(f'only {domain1} can access:')
            for service in services1.values():
                if service.service_name not in services2:
                    print(service)
            print()
            
            print(f'only {domain2} can access:')
            for service in services2.values():
                if service.service_name not in services1:
                    print(service)
            print()
    
    def diff_info_for_domain(self, domain1: SeType, domain2: SeType):
        print(f'printing policy differences between {domain1} and {domain2}')
        self.diff_accessible_services_for_domain(domain1, domain2)
        self.diff_accesible_files_for_domain(domain1, domain2)
        
def dump_selinux_info(setype: str):
    upload_tools()

    context = SelinuxContext()
    context.print_info_for_domain(SeType(setype))

def diff_selinux_info(setype1: str, setype2: str):
    upload_tools()

    context = SelinuxContext()
    context.diff_info_for_domain(SeType(setype1), SeType(setype2))

def dump_selinux():
    # upload_tools()

    ql = CodeqlContext(
        Path('/home/jack/Documents/college/purdue/research/kernelcveanalysis/android_env/codeql_database'),
        Path('/home/jack/Documents/college/purdue/research/kernelcveanalysis/android_env/codeql'),
    )

    # ql.get_aidl_interfaces()

    ql.aidl_flow_to_vuln('android.accounts.IAccountManager', 'android.accounts.IAccountManager.isAccountManagedByCaller') # works

    # ql.methods_in_interface('android.app.role.IRoleManager') # not in db
    # ql.methods_in_interface('android.os.IThermalService')
    # ql.get_type('AccountManagerService')

    # ql.methods_in_interface('android.os.IPermissionController') # methods are messed up, impl name does not match?
    # ql.get_type('IPermissionController')

    # context = SelinuxContext()
    # context.print_info_for_domain(SeType('untrusted_app'))
    # context.print_info_for_domain(SeType('system_server'))
    # context.diff_info_for_domain(SeType('untrusted_app'), SeType('system_server'))

    # a = set(service.service_name for service in get_services_for_permissions(Permissions(uid=10094, gid=10094, selabel='u:r:untrusted_app:s0')))
    # b = set(service.service_name for service in context.accesible_services_for_domain(SeType('untrusted_app')).allowlist)
    # c = set(service.service_name for service in context.accesible_services_for_domain(SeType('untrusted_app'), service_type=ServiceType.HW_SERVICE).allowlist)
    # b = b.union(c)
    # print(len(a))
    # print(len(b))
    # print(a == b)
    # print('only in a')
    # print(a - b)
    # print('only in b')
    # print(b - a)
    # context.accesible_services(SeType('untrusted_app_all'))

    # policy = SePolicy()
    # service_contexts = ServiceContexts()

    # accesible_services(SeType('untrusted_app'), policy, service_contexts)
    # accesible_services(SeType('untrusted_app_all'), policy, service_contexts)
    # accesible_services(SeType('system_app'), policy, service_contexts)
    # accesible_services(SeType('su'), policy, service_contexts)
    # accesible_services(SeType('shell'), policy, service_contexts)
    # accesible_services(SeType('priv_app'), policy, service_contexts)
    # accesible_services(SeType('vold'), policy, service_contexts)