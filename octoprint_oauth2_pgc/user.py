from octoprint.access.users import User


class OAuth2PGCUser(User):
    def __init__(self, username):
        User.__init__(self, username, '', True)
