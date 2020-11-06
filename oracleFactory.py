import smartpy as sp

class Oracle(sp.Contract):
    def __init__(self):
        self.init_type(sp.TRecord(a = sp.TInt, b = sp.TNat))

    @sp.entry_point
    def myEntryPoint(self, params):
        self.data.a += params.x
        self.data.b += params.y

class OracleFactory(sp.Contract):
    def __init__(self):
        self.created = Oracle()
        self.init(list=[])

    @sp.entry_point
    def create(self, params):
        c = sp.create_contract(storage = sp.record(a = 12, b = 15), contract = self.created)
        self.data.list.push(c)

@sp.add_test(name = "Create")
def test():
    scenario = sp.test_scenario()
    scenario.h1("Create Contract")
    baker = sp.test_account("Ma Baker")
    c1 = OracleFactory()
    scenario += c1
    scenario += c1.create()
    scenario += c1.create()
