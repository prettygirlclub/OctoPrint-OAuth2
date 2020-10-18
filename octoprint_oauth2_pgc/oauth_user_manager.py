import logging

from octoprint.util import get_fully_qualified_classname as fqcn
from octoprint.access.users import FilebasedUserManager, User, UserManager, LocalProxy, SessionUser

from octoprint_oauth2_pgc.user import OAuth2PGCUser


class OAuth2PGCBasedUserManager(FilebasedUserManager):
    """
    OAuth2PGCBasedUserManager replaces OctoPrints FilebasedUserManager
    """
    logger = logging.getLogger("octoprint.plugins." + __name__)

    def __init__(self, group_manager, settings):
        OAuth2PGCBasedUserManager.logger.info("Initializing OAuth2PGCBasedUserManager")
        self._group_manager = group_manager
        self._settings = settings

        FilebasedUserManager.__init__(self, group_manager, None, settings)

    def logout_user(self, user):
        """
        Prints log into console, then uses UserManager.logout_user
        """
        self._logger.info("OAuth Logging out")
        UserManager.logout_user(self, user)

    def login_user(self, user):
        """
        This method logs in the user into OctoPrint using authorization OAuth2.
        After that, user is added into users.yaml config file.
        """
        self._cleanup_sessions()

        if user is None or user.is_anonymous:
            return

        if isinstance(user, LocalProxy):
            user = user._get_current_object()
            return user

        if not isinstance(user, User):
            return None

        # -- Overridden parts -----------------------------------------------
        if isinstance(user, OAuth2PGCUser):
            username = user.get_id()
            user = FilebasedUserManager.find_user(self, username)
            if user is None:
                FilebasedUserManager.add_user(self, username, '', active=True)
                user = FilebasedUserManager.find_user(self, username)
        # -- Overridden parts -----------------------------------------------

        if not isinstance(user, SessionUser):
            user = SessionUser(user)

        self._session_users_by_session[user.session] = user

        user_id = user.get_id()
        if user_id not in self._sessionids_by_userid:
            self._sessionids_by_userid[user_id] = set()

        self._sessionids_by_userid[user_id].add(user.session)

        for listener in self._login_status_listeners:
            try:
                listener.on_user_logged_in(user)
            except Exception:
                self._logger.exception("Error in on_user_logged_in on {!r}".format(listener),
                                       extra=dict(callback=fqcn(listener)))

        self._logger.info("Logged in user: {}".format(user.get_id()))

        return user

    def check_password(self, username, password):
        """
        Override checkPassword method to always return False. Use OAuth2 instead
        """
        self._logger.error("Non-OAauth2 based login is not allowed")
        return False
