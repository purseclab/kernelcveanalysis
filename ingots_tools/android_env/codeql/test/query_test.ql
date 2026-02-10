import java

class TargetInterface extends Interface {
    TargetInterface() {
        this.getName() = "IService"
    }
}

predicate isAidlStub(TargetInterface interface, NestedType stub) {
    stub.getEnclosingType() = interface and stub.getName() = "Stub"
}

from TargetInterface interface, NestedType stub, RefType impl
where isAidlStub(interface, stub)
and impl.extendsOrImplements(stub)
select interface, stub, impl
