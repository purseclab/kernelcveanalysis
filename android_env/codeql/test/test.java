package com.example;

class Test {
    static void test() {
        // IService.Stub a = new IService.Stub() {};
    }
}

interface IService {
    public void aidl_method(int a);

    interface Stub extends IService {
        public void aidl_method(int a);
    }
}

class Service implements IService.Stub {
    void target_method(int vuln) {
        System.out.println(vuln);
    }

    public void aidl_method(int a) {
        target_method(a);
    }
}
