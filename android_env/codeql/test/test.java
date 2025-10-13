class Test {
    static void test() {
        IService.Stub a = new IService.Stub() {};
    }
}

interface IService {
    interface Stub {}
}

class Service implements IService.Stub {}
