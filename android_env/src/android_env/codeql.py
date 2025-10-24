from pathlib import Path
from enum import StrEnum
from tempfile import TemporaryDirectory
import shutil
import subprocess
import json
import textwrap

QUERY_COMMON = textwrap.indent('''
import java

predicate isAidlStub(Interface interface, NestedType stub) {
    stub.getEnclosingType() = interface and stub.getName() = "Stub" and stub.extendsOrImplements(interface)
}

predicate methodOverridesMember(RefType type, Method m) {
    m.getAnOverride().getDeclaringType() = type
}

class AidlInterface extends Interface {
    NestedType stub;

    AidlInterface() {
        isAidlStub(this, stub)
    }

    NestedType getStub() {
        result = stub
    }
}

class AidlImpl extends RefType {
    AidlInterface interface;

    AidlImpl() {
        this.extendsOrImplements(interface.getStub())
    }

    AidlInterface getInterface() {
        result = interface
    }
}

class AidlMethodImpl extends Method {
    AidlImpl impl;

    AidlMethodImpl() {
        this.getDeclaringType() = impl
        and methodOverridesMember(impl.getInterface(), this)
    }

    AidlImpl getImpl() {
        result = impl
    }
}
''', '        ')

class CodeqlQuery(StrEnum):
    TestQuery = 'test.ql'
    GetAidlImpl = 'get_aidl_impl.ql'

class CodeqlContext:
    database_path: Path
    query_folder: Path

    def __init__(self, database_path: Path, query_folder: Path):
        self.database_path = database_path
        self.query_folder = query_folder

    def run_query_str(self, query: str) -> list[tuple]:
        query = textwrap.dedent(query)
        print(f'running query:\n{query}')

        with TemporaryDirectory() as dir:
            query_path = dir + '/query.ql'
            bqrs_path = dir + '/output.bqrs'
            json_path = dir + '/output.json'

            with open(query_path, 'w') as f:
                f.write(query)
            
            shutil.copyfile(self.query_folder / 'qlpack.yml', dir + '/qlpack.yml')

            subprocess.run(
                ['codeql', 'query', 'run', query_path, '--database', str(self.database_path), '--output', bqrs_path],
                cwd=dir,
                check=True,
            )

            subprocess.run(
                ['codeql', 'bqrs', 'decode', bqrs_path, '--output', json_path, '--format', 'json']
            )

            with open(json_path, 'r') as f:
                data = json.loads(f.read())
            
            rows = data['#select']['tuples']

            def flatten_row(row: list[dict[str, str] | str]) -> tuple:
                return tuple(item if type(item) == str else item['label'] for item in row)
            
            return [flatten_row(row) for row in rows]
    
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

    def target_interface(self, codeql_name: str, interface_paths: list[str]) -> str:
        '''
        Returns a codeql class named `codeql_name` which is a type which resolves to a specific set of interfaces.
        '''

        def match_line(interface_path: str) -> str:
            parts = interface_path.split('.')
            package = '.'.join(parts[:-1])
            interface = parts[-1]
            return f'this.hasQualifiedName("{package}", "{interface}")'
        
        body = ' or '.join(match_line(interface) for interface in interface_paths)

        return f'''
        class {codeql_name} extends Interface {{
            {codeql_name}() {{
                {body}
            }}
        }}
        '''
    
    def target_method(self, codeql_name: str, method_path: str) -> str:
        '''
        Returns a codeql class named `codeql_name` which is a specific method
        '''

        parts = method_path.split('.')
        package = '.'.join(parts[:-2])
        class_name = parts[-2]
        method_name = parts[-1]

        return f'''
        class {codeql_name} extends Method {{
            {codeql_name}() {{
                this.hasQualifiedName("{package}", "{class_name}", "{method_name}")
            }}
        }}
        '''
    
    # this one is mostly just for debugging to see if a type is actually in the database
    def get_type(self, type_name: str):
        query = f'''
        import java

        from RefType type
        where type.getName() = "{type_name}"
        select type.getName(), type.getPackage()
        '''
        print(self.run_query_str(query))
    
    def get_method(self, method_path: str):
        parts = method_path.split('.')
        package = '.'.join(parts[:-2])
        class_name = parts[-2]
        method_name = parts[-1]

        query = f'''
        import java

        from Method m
        where m.hasQualifiedName("{package}", "{class_name}", "{method_name}")
        select m
        '''
        
        print(self.run_query_str(query))
    
    def aidl_impl(self, interface_path: str):
        # mostly for debugging

        query = f'''
        {QUERY_COMMON}

        {self.target_interface('TargetInterface', [interface_path])}

        from TargetInterface interface, AidlImpl impl
        where impl.getInterface() = interface
        select interface, impl
        '''

        print(self.run_query_str(query))
    
    def aidl_methods(self, interface_path: str):
        # mostly for debugging

        query = f'''
        {QUERY_COMMON}

        {self.target_interface('TargetInterface', [interface_path])}

        from TargetInterface interface, AidlMethodImpl method
        where method.getImpl().getInterface() = interface
        select interface, method
        '''

        print(self.run_query_str(query))
    
    def aidl_flow_to_vuln(self, interface_paths: list[str], vuln_method_path: str):
        query = f'''
        import semmle.code.java.dataflow.DataFlow
        import semmle.code.java.dataflow.TaintTracking

        {QUERY_COMMON}

        {self.target_interface('TargetInterface', interface_paths)}
        {self.target_method('VulnMethod', vuln_method_path)}

        module FlowConfig implements DataFlow::ConfigSig {{
            predicate isSource(DataFlow::Node source) {{
                exists(TargetInterface interface, AidlMethodImpl m
                    | m.getImpl().getInterface() = interface
                    | source.asParameter().getCallable() = m
                )
            }}

            predicate isSink(DataFlow::Node source) {{
                exists(VulnMethod m | source.asParameter().getCallable() = m)
            }}

            /*predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {{
                exists(BinaryExpr be |
                    be.getAnOperand() = a.asExpr() and
                    b.asExpr() = be
                )
            }}*/
        }}

        module MyFlow = TaintTracking::Global<FlowConfig>;

        /*from Flow::PathNode source, Flow::PathNode sink
        where Flow::flowPath(source, sink)
        select source, sink*/

        from TargetInterface interface, AidlMethodImpl method, DataFlow::Node source, DataFlow::Node sink, DataFlow::Node next
        where method.getImpl().getInterface() = interface
        and source.asParameter().getCallable() = method
        and MyFlow::flow(source, sink)
        select interface, method, source, sink

        '''
        
        print(self.run_query_str(query))

    def get_aidl_interfaces(self):
        query = f'''
        {QUERY_COMMON}

        from Interface interface, NestedType stub
        where isAidlStub(interface, stub)
        select interface
        '''

        print(self.run_query_str(query))
    
    def taint_test(self):
        query = f'''
        import java

        {self.target_method('SrcMethod', 'com.example.Test.testLocalSrc')}
        {self.target_method('DstMethod', 'com.example.Test.testLocalDst')}

        import semmle.code.java.dataflow.DataFlow
        import semmle.code.java.dataflow.TaintTracking

        module FlowConfig implements DataFlow::ConfigSig {{
            predicate isSource(DataFlow::Node source) {{
                exists(SrcMethod m | source.asParameter().getCallable() = m)
            }}

            predicate isSink(DataFlow::Node source) {{
                exists(DstMethod m | source.asParameter().getCallable() = m)
            }}
        }}

        module MyFlow = TaintTracking::Global<FlowConfig>;

        from DataFlow::Node src, DataFlow::Node dst
        where MyFlow::flow(src, dst)
        select src, dst

        /*from SrcMethod m, Parameter a, DataFlow::Node dst
        where a.getCallable() = m
        and TaintTracking::localTaint(DataFlow::parameterNode(a), dst)
        select m, a, dst*/
        '''

        print(self.run_query_str(query))

def codeql_test():
    # Real database
    # db = Path('/home/jack/Documents/college/purdue/research/kernelcveanalysis/android_env/codeql_database')

    # Test database
    db = Path('/home/jack/Documents/college/purdue/research/kernelcveanalysis/android_env/codeql/test/test_db')


    ql = CodeqlContext(
        db,
        Path('/home/jack/Documents/college/purdue/research/kernelcveanalysis/android_env/codeql'),
    )

    ql.taint_test()
    # ql.aidl_flow_to_vuln(['com.example.IGoofy'], 'com.example.Test.test')
    # ql.aidl_flow_to_vuln(['com.example.IService', 'com.example.IGoofy'], 'com.example.Test.test')
    # ql.get_type('IService')
    # ql.get_method('com.example.Service.target_method')


    # ql.get_aidl_interfaces()

    # ql.aidl_flow_to_vuln(['android.accounts.IAccountManager'], 'com.android.server.accounts.AccountManagerService.isAccountManagedByCaller') # works
    # ql.aidl_impl('android.accounts.IAccountManager') # works
    # ql.get_method('com.android.server.accounts.AccountManagerService.isAccountManagedByCaller')
    # ql.get_type('AccountManagerService')

    # ql.aidl_flow_to_vuln('android.app.role.IRoleManager') # not in db
    # ql.aidl_flow_to_vuln('android.os.IThermalService')
    # ql.get_type('AccountManagerService')

    # ql.aidl_flow_to_vuln('android.os.IPermissionController') # methods are messed up, impl name does not match?
    # ql.get_type('IPermissionController')