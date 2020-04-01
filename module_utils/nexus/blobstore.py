class Blobstore:
    def __init__(self, **kwargs):
        if 'name' in kwargs:
            self.name = kwargs['name']
        else:
            self.name = None
        if 'path' in kwargs:
            self.path = kwargs['path']
        else:
            self.path = None
        if 'soft_quota_enabled' in kwargs:
            self.soft_quota_enabled = kwargs['soft_quota_enabled']
        else:
            self.soft_quota_enabled = None
        if 'soft_quota_type' in kwargs:
            self.soft_quota_type = kwargs['soft_quota_type']
        else:
            self.soft_quota_type = None
        if 'soft_quota_limit' in kwargs:
            self.soft_quota_limit = kwargs['soft_quota_limit']
        else:
            self.soft_quota_limit = None


    @property
    def get_name(self):
        return self._name

    @property
    def set_name(self, value):
        return self._name

    @property
    def get_path(self):
        return self._path

    @property
    def set_path(self, value):
        return self._path

    @property
    def get_soft_quota_enabled(self):
        return self._soft_quota_enabled

    @property
    def set_soft_quota_enabled(self, value):
        return self._soft_quota_enabled

    @property
    def get_soft_quota_type(self):
        return self._soft_quota_type

    @property
    def set_soft_quota_type(self, value):
        if value == 'Space-Remaining' or value == 'spaceRemainingQuota':
            self._soft_quota_type = 'spaceRemainingQuota'
        elif value == 'Space-Used' or value == 'spaceUsedQuota':
            self._soft_quota_type = 'spaceUsedQuota'
        else:
            self._soft_quota_type = None

    @property
    def get_soft_quota_limit(self):
        return self._soft_quota_limit

    @property
    def set_soft_quota_limit(self, value):
        if value < 1:
            value = 1
        self._soft_quota_limit = value * 1000 * 1000

    def is_valid(self):
        if self.soft_quota_enabled == 'Enabled':
            if self.soft_quota_type is None or self.soft_quota_limit is None:
                return False, 'Quota is Enabled, Type and Limit must be defined'
            else:
                return True, 'no failure'

    def build_json(self):
        data = {}
        data['path'] = self.path
        data['name'] = self.name
        if soft_quota_enabled == 'Enabled':
            quota = {}
            quota['type'] = self.soft_quota_type
            quota['limit'] = self.soft_quota_limit
            data['softQuota'] = quota
        return data