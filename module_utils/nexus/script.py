class Script:
    def __init__(self, **kwargs):
        if 'name' in kwargs:
            self.name = kwargs['name']
        else:
            self.name = None
        if 'content' in kwargs:
            self.content = kwargs['content']
        else:
            self.content = None
        if 'path_to_content' in kwargs:
            self.path_to_content = kwargs['path_to_content']
        else:
            self.path_to_content = None
        if 'content_type' in kwargs:
            self.content_type = kwargs['content_type']
        else:
            self.content_type = None


    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @property
    def content(self):
        return self.__content

    @content.setter
    def content(self, value):
        self.__content = value

    @property
    def path_to_content(self):
        return self.__path_to_content

    @path_to_content.setter
    def path_to_content(self, value):
        self.__path_to_content = value

    @property
    def content_type(self):
        return self.__content_type

    @content_type.setter
    def content_type(self, value):
        self.__content_type = value

    def to_dict(self):
        dict = {}
        if self.name is not None:
            dict['name'] = self.name
        if self.content is not None:
            dict['content'] = self.content
        if self.content is None and self.path_to_content is not None:
            try:
                dict['content'] = open(self.path_to_content, 'rb')
            except FileNotFoundError:
                raise Exception('Could not locate or open file= ' + self.path_to_content)
        if self.content_type is not None:
            dict['type'] = self.content_type
        return dict

