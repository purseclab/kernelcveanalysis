from typing import NewType, TypeVar, Callable, Self, Optional
from pathlib import Path
from tempfile import NamedTemporaryFile
from dataclasses import dataclass
from collections import defaultdict
from itertools import chain
import subprocess
import itertools

from .adb import read_file, run_adb_command, runas, Permissions
from .util import config_lines

T = TypeVar('T')

SELINUX_CONFIG_DIR = '/system/etc/selinux'
SELINUX_APP_CONTEXTS = f'{SELINUX_CONFIG_DIR}/plat_seapp_contexts'
SELINUX_SERVICE_CONTEXTS = f'{SELINUX_CONFIG_DIR}/plat_service_contexts'

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

class ServiceContexts:
    '''
    This class represents all information from `/system/etc/selinux/plat_service_contexts` file.

    So it handles mapping service names to selinux domains.
    '''
    # map from service name to SeLabel
    services: dict[str, SeLabel]
    fallback: SeLabel

    def __init__(self):
        self.services = {}

        config = read_file(SELINUX_SERVICE_CONTEXTS).decode('utf-8')

        for line in config_lines(config):
            parts = line.split()
            if parts[0] == '*':
                self.fallback = SeLabel.parse(parts[1])
            else:
                self.services[parts[0]] = SeLabel.parse(parts[1])
        
        assert self.fallback
    
    def label_to_service_name_map(self) -> dict[SeLabel, list[str]]:
        out = defaultdict(list)
        for service, label in self.services.items():
            out[label].append(service)
        
        return dict(out)
    
    def get_selabel(self, service_name: str) -> SeLabel:
        if service_name in self.services:
            return self.services[service_name]
        else:
            return self.fallback
    
    # doesn't check fallback services
    def services_for_setype(self, setype: SeType) -> list[str]:
        return [service for service, label in self.services.items() if label.type == setype]


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
            permissions = list(parts[3])

        
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
        sesearch_output = self.sesearch([
            '--allow',
            # search for service manager class
            '-c', clazz,
            # for rules with find permission
            '-p', permission,
        ])

        return AllowRule.parse_many_rules(sesearch_output)

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

class SelinuxContext:
    policy: SePolicy
    services: ServiceContexts
    # mapping from type to service types it can access
    accessible_service_map: dict[SeType, list[SeType]]
    # mapping from service name to service info
    service_interfaces: dict[str, ServiceInfo]

    def __init__(self):
        self.policy = SePolicy()
        self.services = ServiceContexts()

        accessible_service_map = defaultdict(list)
        # relevant code: https://cs.android.com/android/platform/superproject/main/+/main:system/hwservicemanager/AccessControl.cpp
        rules = self.policy.rules_for_permission('service_manager', 'find')
        for rule in self.policy.expand_rule_attributes(rules):
            accessible_service_map[rule.source_type].append(rule.dst_type)
        self.accessible_service_map = dict(accessible_service_map)

        self.service_interfaces = {}
        for service in get_services_for_permissions(Permissions.root()):
            self.service_interfaces[service.service_name] = service
    
    def service_names_to_service_info(self, service_names: list[str]) -> list[ServiceInfo]:
        return [
            self.service_interfaces[service] for service in service_names
            if service in self.service_interfaces
        ]
    
    def accesible_services_for_domain(self, domain_type: SeType) -> AccessibleServices:
        can_access_fallback = False

        # check if no services are accessible
        if domain_type not in self.accessible_service_map:
            return AccessibleServices(
                allowlist=[],
                blocklist=None,
            )

        accesible_services = self.accessible_service_map[domain_type]
        can_access_fallback = self.services.fallback.type in accesible_services

        service_names = []
        for type in accesible_services:
            service_names.extend(self.services.services_for_setype(type))
        
        forbidden_services = None
        if can_access_fallback:
            all_services = self.services.label_to_service_name_map()
            for type in accesible_services:
                if type in all_services:
                    del all_services[type]
            
            forbidden_services = list(chain.from_iterable(all_services.values))
        
        return AccessibleServices(
            allowlist=self.service_names_to_service_info(service_names),
            blocklist=None if forbidden_services is None else self.service_names_to_service_info(forbidden_services),
        )
    
    def accesible_services(self, domain_type: SeType):
        services = self.accesible_services_for_domain(domain_type)

        print(f'{domain_type} can access:')
        for service in services.allowlist:
            print(service)
        
        print(f'Can access fallback: {services.blocklist is not None}')
        if services.blocklist is not None:
            for service in services.blocklist:
                print(service)
        
        print()

def dump_selinux():
    # print(get_services_for_permissions(Permissions(uid=10094, gid=10094, selabel='u:r:untrusted_app:s0')))
    context = SelinuxContext()
    context.accesible_services(SeType('untrusted_app'))
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