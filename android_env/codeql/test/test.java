package com.example;

class Test {
    static void test(int a) {
        // IService.Stub a = new IService.Stub() {};
    }

    static void testLocalSrc(String src) {
        String b = src + "a";
        String c = b;
        testLocalDst(c);
    }

    static void testLocalDst(String dst) {
        System.out.println(dst);
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
        Test.test(vuln);
        System.out.println(vuln);
    }

    public void aidl_method(int c) {
        target_method(c);
    }
}

interface IGoofy {
    public void goofy_method(int a, int b);

    interface Stub extends IGoofy {
        public void goofy_method(int a, int b);
    }
}

class GoofyImpl implements IGoofy.Stub {
    public void goofy_method(int a, int b) {
        if (b == 0) {
            int dumb = a + 5;
            Test.test(dumb);
        } else {
            Test.test(b);
        }
    }
}
