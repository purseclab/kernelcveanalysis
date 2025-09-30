from typing import NewType, TypeVar, Callable, Self
from pathlib import Path
from tempfile import NamedTemporaryFile
from dataclasses import dataclass
import subprocess

from .adb import read_file
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
    permission: str

    @classmethod
    def parse_from_rule(cls, rule: str) -> Self:
        rule = rule.strip()
        if rule.endswith(';'):
            rule = rule[:-1]
        
        parts = rule.split()
        assert parts[0] == 'allow'
        
        return cls(
            source_type=SeType(parts[1]),
            dst_type=SeType(parts[2].split(':')[0]),
            seclass=SeClass(parts[2].split(':')[1]),
            # FIXME: some permission are in brackets for some reason
            permission=parts[3],
        )
    
    # use for sesearch output for example
    @classmethod
    def parse_many_rules(cls, rules: str) -> list[Self]:
        return [
            cls.parse_from_rule(line.strip())
            for line in rules.split('\n') if line.strip() != ''
        ]

class SePolicy:
    policy: bytes
    accessible_service_map: dict[SeType, list[SeType]]

    def __init__(self):
        self.policy = read_file('/sys/fs/selinux/policy')
        self.compute_accessible_service_map()

    def with_policy_file(self, callback: Callable[[Path], T]) -> T:
        with NamedTemporaryFile() as f:
            f.write(self.policy)
            f.flush()
            return callback(Path(f.name))
    
    def compute_accessible_service_map(self) -> dict[SeType, list[SeType]]:
        rules = self.search_service_rules()
        self.accessible_service_map = {}

        for rule in rules:
            if rule.source_type not in self.accessible_service_map:
                self.accessible_service_map[rule.source_type] = []
            
            self.accessible_service_map[rule.source_type].append(rule.dst_type)
    
    def sesearch(self, args: list[str]) -> str:
        def run_sesearch(file: Path) -> str:
            search_args = ['sesearch', str(file)]
            search_args.extend(args)

            return subprocess.run(
                search_args,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        
        return self.with_policy_file(run_sesearch)
    
    # relevant code: https://cs.android.com/android/platform/superproject/main/+/main:system/hwservicemanager/AccessControl.cpp
    def search_service_rules(self) -> list[AllowRule]:
        sesearch_output = self.sesearch([
            '--allow',
            # search for service manager class
            '-c', 'service_manager',
            # for rules with find permission
            # TODO: figure out why this returns add find as well, and what that even means
            '-p', 'find'
        ])

        rules = AllowRule.parse_many_rules(sesearch_output)
        # exclude { add find } rules
        return [rule for rule in rules if rule.permission == 'find']

    def accessible_services_for_domain(self, domain_type: SeType) -> list[SeType]:
        return self.accessible_service_map[domain_type]
    
def accesible_services(domain_type: SeType, policy: SePolicy, services: ServiceContexts):
    can_access_fallback = False
    service_names = []

    for type in policy.accessible_services_for_domain(domain_type):
        service_names.extend(services.services_for_setype(type))
        if services.fallback.type == type:
            can_access_fallback = True
    
    print('Can access')
    for service in service_names:
        print(service)
    
    print(f'Can access fallback: {can_access_fallback}')

def dump_selinux():
    policy = SePolicy()
    service_contexts = ServiceContexts()
    print(policy.accessible_services_for_domain(SeType('untrusted_app')))

    accesible_services(SeType('untrusted_app'), policy, service_contexts)