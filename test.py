

class TestClass():
    _app = 'test_string'
    
    @classproperty
    def app(cls):
        return cls._app
    
    @app.setter
    def app(cls, value):
        cls._app = value

class ChildClass(TestClass):
    pass

