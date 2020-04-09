class Component:
    def __init__(self, **kwargs):
        if 'id' in kwargs:
            self.id = kwargs['id']
        else:
            self.id = None
        if 'repository' in kwargs:
            self.repository = kwargs['repository']
        else:
            self.repository = None
        if 'format' in kwargs:
            self.format = kwargs['format']
        else:
            self.format = None
        if 'group' in kwargs:
            self.group = kwargs['group']
        else:
            self.group = None
        if 'name' in kwargs:
            self.name = kwargs['name']
        else:
            self.name = None
        if 'version' in kwargs:
            self.version = kwargs['version']
        else:
            self.version = None
        #if 'assets' in kwargs:
        #    self.assets = {}
        #    for x in kwargs['assets']:
        #        self.assets.update(x)
        #else:
        #    self.assets = None

    @property
    def id(self):
        return self.__id

    @id.setter
    def id(self, value):
        self.__id = value

    @property
    def repository(self):
        return self.__repository

    @repository.setter
    def repository(self, value):
        self.__repository = value

    @property
    def format(self):
        return self.__format

    @format.setter
    def format(self, value):
        self.__format = value

    @property
    def group(self):
        return self.__group

    @group.setter
    def group(self, value):
        self.__group = value

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @property
    def version(self):
        return self.__version

    @version.setter
    def version(self, value):
        self.__version = value

    def to_dict(self):
        dict = {}

