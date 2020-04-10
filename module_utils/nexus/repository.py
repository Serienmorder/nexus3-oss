class Repository:
    def __init__(self, **kwargs):
        if 'name' in kwargs:
            self.name = kwargs['name']
        else:
            self.name = None
        if 'format' in kwargs:
            self.format = kwargs['format']
        else:
            self.format = None


    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @property
    def format(self):
        return self.__format

    @format.setter
    def format(self, value):
        self.__format = value
