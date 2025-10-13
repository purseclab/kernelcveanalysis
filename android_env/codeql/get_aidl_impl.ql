/**
 * @name Find implementations of AIDL interfaces
 * @param interfaceName string name of interface
 * @param package string package interface is in
 */

import java

class TargetInterface extends Interface {
    TargetInterface() {
        this.hasQualifiedName(package, interfaceName)
    }
}

predicate isAidlStub(TargetInterface interface, NestedType stub) {
    stub.getEnclosingType() = interface and stub.getName() = "Stub"
}

from TargetInterface interface, NestedType stub, RefType impl
where isAidlStub(interface, stub)
and impl.extendsOrImplements(stub)
select interface, stub, impl
