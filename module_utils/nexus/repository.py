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
        if 'health_check' in kwargs:
            self.health_check = kwargs['health_check']
        else:
            self.health_check = False
        if 'rebuild_index' in kwargs:
            self.rebuild_index = kwargs['rebuild_index']
        else:
            self.rebuild_index = False


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

    @property
    def health_check(self):
        return self.__health_check

    @health_check.setter
    def health_check(self, value):
        self.__health_check = value

    @property
    def rebuild_index(self):
        return self.__rebuild_index

    @rebuild_index.setter
    def rebuild_index(self, value):
        self.__rebuild_index = value

    @property
    def invalidate_cache(self):
        return self.__invalidate_cache

    @invalidate_cache.setter
    def invalidate_cache(self, value):
        self.__invalidate_cache = value

