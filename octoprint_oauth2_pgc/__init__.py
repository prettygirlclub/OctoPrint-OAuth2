# coding=utf-8
from __future__ import absolute_import

import json

import flask
import flask_login
import octoprint.plugin
import logging

import requests
from oauthlib.oauth2 import WebApplicationClient
from octoprint.access.permissions import Permissions
from octoprint.events import eventManager, Events
from octoprint.server.util.flask import get_remote_address
from octoprint.vendor.flask_principal import identity_changed, Identity

from octoprint_oauth2_pgc.oauth_user_manager import OAuth2PGCBasedUserManager
from octoprint_oauth2_pgc.settings import settings_defaults

from octoprint_oauth2_pgc.user import OAuth2PGCUser


class OAuth2PGCPlugin(octoprint.plugin.StartupPlugin,
                      octoprint.plugin.TemplatePlugin,
                      octoprint.plugin.SettingsPlugin,
                      octoprint.plugin.AssetPlugin,
                      octoprint.plugin.UiPlugin,
                      octoprint.plugin.BlueprintPlugin):

    def __init__(self):
        pass

    @property
    def active(self):
        # we are only active if ACL is enabled AND configured
        return self._user_manager.enabled and self._user_manager.has_been_customized()

    ##~~ TemplatePlugin mixin

    def get_template_configs(self):
        return [
            dict(type="navbar", template="oauth2_pgc_login.jinja2", custom_bindings=False, replaces="login"),
            dict(type="settings", custom_bindings=False)
        ]

    ##~~ SettingsPlugin mixin

    def get_settings_defaults(self):
        return settings_defaults()

    def get_settings_restricted_paths(self):
        """
        Set restricted paths of config.yaml
        """
        return dict(admin=[["plugins", "oauth2_pgc"], ])

    ##~~ AssetPlugin mixin

    def get_assets(self):
        return dict(
            js=["js/oauth2_pgc_viewmodel.js"],
        )

    ##~~ Softwareupdate hook

    def get_update_information(self):
        return dict(
            oauth2_pgc=dict(
                displayName="PGC OAuth2 Login Plugin",
                displayVersion=self._plugin_version,

                # version check: github repository
                type="github_release",
                user="prettygirlclub",
                repo="OctoPrint-OAuth2",
                current=self._plugin_version,

                # update method: pip
                pip="https://github.com/prettygirlclub/OctoPrint-OAuth2/archive/{target_version}.zip"
            )
        )

    def on_after_startup(self):
        self._logger.info("Hallå biblan hur är läget?!")

    ##~~ UIPlugin mixin

    def will_handle_ui(self, request):
        if not self.active:
            # not active, not responsible
            return False

        from octoprint.server.util import loginUserFromApiKey, loginUserFromAuthorizationHeader, \
            InvalidApiKeyException
        from octoprint.server.util.flask import passive_login

        # first try to login via api key & authorization header, just in case that's set
        try:
            if loginUserFromApiKey():
                # successful? No need for handling the UI
                return False
        except InvalidApiKeyException:
            pass  # ignored

        if loginUserFromAuthorizationHeader():
            # successful? No need for handling the UI
            return False

        # then try a passive login
        passive_login()
        if Permissions.STATUS.can() and Permissions.SETTINGS_READ.can():
            # Status & settings_read permission? No need to handle UI
            return False
        else:
            return True

    def on_ui_render(self, now, request, render_kwargs):
        from flask import render_template, make_response

        def add_additional_assets(hook):
            result = []
            for name, hook in self._plugin_manager.get_hooks(hook).items():
                try:
                    assets = hook()
                    if isinstance(assets, (tuple, list)):
                        result += assets
                except:
                    self._logger.exception("Error fetching theming CSS to include from plugin {}".format(name),
                                           extra=dict(plugin=name))
            return result

        additional_assets = []
        additional_assets += add_additional_assets("octoprint.plugin.loginui.theming")

        render_kwargs.update(dict(loginui_theming=additional_assets))
        return make_response(render_template("oauth2_pgc_index.jinja2", **render_kwargs))

    def get_ui_custom_tracked_files(self):
        from os.path import join as opj

        paths = [opj("static", "css", "oauth2_pgc_login.css"),
                 opj("static", "js", "oauth2_pgc_main.js"),
                 opj("static", "js", "oauth2_pgc_viewmodel.js"),
                 opj("templates", "parts", "oauth2_pgc_login_css.jinja2"),
                 opj("templates", "parts", "oauth2_pgc_login_javascripts.jinja2"),
                 opj("templates", "oauth2_pgc_index.jinja2")]

        return [opj(self._basefolder, path) for path in paths]

    def get_ui_preemptive_caching_enabled(self):
        return False

    def get_sorting_key(self, context=None):
        if context == "UiPlugin.on_ui_render":
            # If a plugin *really* wants to come before this plugin, it'll have to turn to negative numbers.
            #
            # This is obviously discouraged for security reasons, but very specific setups might make it necessary,
            # so we make it possible. If this should get abused long term we can always turn this into -inf.
            return -1

    """
    Don't require being logged in to use login endpoints
    """
    def is_blueprint_protected(self):
        return False

    @octoprint.plugin.BlueprintPlugin.route("/redirect", methods=["POST"])
    def api_auth_redirect(self):
        s = self._settings

        authorization_endpoint = s.get(['authorization_endpoint'])
        client_id = s.get(['client_id'])
        callback_base_url = s.get(['callback_base_url'])

        client = WebApplicationClient(client_id)

        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=callback_base_url + "/plugin/oauth2_pgc/callback",
            scope=["email", "read:org"],
        )

        return flask.redirect(request_uri)

    @octoprint.plugin.BlueprintPlugin.route("/callback", methods=["GET"])
    def api_auth_callback(self):
        s = self._settings
        d = settings_defaults()

        code = flask.request.args.get("code")

        token_endpoint = s.get(['token_endpoint'])
        client_id = s.get(['client_id'])
        client_secret = s.get(['client_secret'])
        userinfo_endpoint = s.get(['userinfo_endpoint'])
        orguser_endpoint = s.get(['orguser_endpoint'])
        organization = s.get(['organization'])
        username_key = s.get(['username_key'])

        self._logger.info('token_endpoint: ' + str(token_endpoint))

        client = WebApplicationClient(client_id)

        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            # authorization_response=flask.request.url,
            # redirect_url=flask.request.base_url,
            code=code
        )

        headers['Accept'] = 'application/json'

        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(client_id, client_secret),
        )

        client.parse_request_body_response(json.dumps(token_response.json()))

        uri, headers, body = client.add_token(userinfo_endpoint)
        headers['Accept'] = 'application/json'
        userinfo_response = requests.get(uri, headers=headers, data=body)

        userinfo = userinfo_response.json()
        username = userinfo[username_key]

        uri, headers, body = client.add_token(orguser_endpoint.format(organization, username))
        headers['Accept'] = 'application/json'
        orguser_response = requests.get(uri, headers=headers, data=body)

        if orguser_response.status_code == 204:
            # User is part of the specified organization, find user or create it if it doesn't exist
            user = self._user_manager.login_user(OAuth2PGCUser(username))
            flask.session["usersession.id"] = user.session
            flask.g.user = user

            self._logger.info("authenticated: " + str(user.is_authenticated))
            self._logger.info("user: " + str(user.as_dict()))

            flask_login.login_user(user, remember=False)
            identity_changed.send(flask.current_app._get_current_object(), identity=Identity(user.get_id()))
            remote_addr = get_remote_address(flask.request)
            logging.getLogger(__name__).info("Actively logging in user {} from {}".format(user.get_id(), remote_addr))

            r = flask.redirect('/')
            r.delete_cookie("active_logout")

            eventManager().fire(Events.USER_LOGGED_IN, payload=dict(username=user.get_id()))

            return r

        return flask.redirect('/?error=unauthorized')


def user_factory_hook(components, settings, *args, **kwargs):
    """
    User factory hook, to inititialize OAuthBasedUserManager, which controls login users
    """
    logger = logging.getLogger("octoprint.plugins." + __name__)
    logger.info("Running octoprint.access.users.factory hook => OAuth2PGCBasedUserManager")

    if settings.get(["plugins", "oauth2_pgc"]) is None:
        logger.error('Plugin configuration missing!')
        return None

    if not settings.get(["accessControl", "enabled"]):
        logger.error('AccessControl is disabled!')
        return None

    group_manager = components["group_manager"]
    return OAuth2PGCBasedUserManager(group_manager, settings)


__plugin_name__ = "PGC OAuth2 Login"
__plugin_pythoncompat__ = ">=2.7,<4"  # python 2 and 3


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = OAuth2PGCPlugin()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
        "octoprint.access.users.factory": user_factory_hook
    }
