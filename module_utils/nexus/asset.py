class Asset:
    def __init__(self, **kwargs):
        self.download_url = kwargs['downloadUrl']
        self.path = kwargs['path']
        self.id = kwargs['id']
        self.repository = kwargs['repository']
        self.format = kwargs['yum']
        self.checksum = {}
        for x in kwargs['checksum']:
            checksum.update(x)

    @property
    def download_url(self):
        return self.__download_url

    @download_url.setter
    def download_url(self, value):
        self.__download_url = value

    @property
    def path(self):
        return self.__path

    @path.setter
    def path(self, value):
        self.__path = value

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
