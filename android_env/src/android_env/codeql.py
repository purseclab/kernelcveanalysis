from pathlib import Path
from enum import StrEnum
from tempfile import TemporaryDirectory
import shutil
import subprocess

class CodeqlQuery(StrEnum):
    TestQuery = 'test.ql'
    GetAidlImpl = 'get_aidl_impl.ql'

class CodeqlContext:
    database_path: Path
    query_folder: Path

    def __init__(self, database_path: Path, query_folder: Path):
        self.database_path = database_path
        self.query_folder = query_folder

    def run_query_str(self, query: str) -> str:
        with TemporaryDirectory() as dir:
            query_path = dir + '/query.ql'
            bqrs_path = dir + '/output.bqrs'
            csv_path = dir + '/output.csv'

            with open(query_path, 'w') as f:
                f.write(query)
            
            shutil.copyfile(self.query_folder / 'qlpack.yml', dir + '/qlpack.yml')

            subprocess.run(
                ['codeql', 'query', 'run', query_path, '--database', str(self.database_path), '--output', bqrs_path],
                cwd=dir,
                check=True,
            )

            subprocess.run(
                ['codeql', 'bqrs', 'decode', bqrs_path, '--output', csv_path, '--format', 'csv']
            )

            with open(csv_path, 'r') as f:
                data = f.read()
        
        return data
    
    def run_query(self, query: CodeqlQuery, **kwargs: str) -> str:
        script_args = []
        for arg_name, arg_value in kwargs.items():
            script_args.extend(('--parameter', f'{arg_name}={arg_value}'))

        with TemporaryDirectory() as dir:
            query_path = self.query_folder / str(query)
            bqrs_path = dir + '/output.bqrs'
            csv_path = dir + '/output.csv'

            subprocess.run(
                ['codeql', 'query', 'run', str(query_path), '--database', str(self.database_path), '--output', bqrs_path] + script_args,
                cwd=str(self.query_folder),
                check=True,
            )

            subprocess.run(
                ['codeql', 'bqrs', 'decode', bqrs_path, '--output', csv_path, '--format', 'csv']
            )

            with open(csv_path, 'r') as f:
                data = f.read()
        
        return data

    
    # this one is mostly just for debugging to see if a type is actually in the database
    def get_type(self, type_name: str):
        query = f'''
import java

from RefType type
where type.getName() = "{type_name}"
select type.getName()
'''
        print(self.run_query_str(query))
    
    def methods_in_interface(self, interface_path: str):
        parts = interface_path.split('.')
        package = '.'.join(parts[:-1])
        interface = parts[-1]

        query = f'''
import java

class TargetInterface extends Interface {{
    TargetInterface() {{
        this.hasQualifiedName("{package}", "{interface}")
    }}
}}

predicate isAidlStub(TargetInterface interface, NestedType stub) {{
    stub.getEnclosingType() = interface and stub.getName() = "Stub"
}}

predicate methodOverridesMember(RefType type, Method m) {{
    m.getAnOverride().getDeclaringType() = type
}}

from TargetInterface interface, NestedType stub, RefType impl, Method m
where isAidlStub(interface, stub)
and impl.extendsOrImplements(stub)
and m.getDeclaringType() = impl
// the aidl methods are declared in the interface
and methodOverridesMember(interface, m)
select interface, stub, impl, m, m.getAnOverride().getDeclaringType()
'''
        print(query)
        
        print(self.run_query_str(query))
