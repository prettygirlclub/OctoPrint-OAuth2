/*
 * View model for OctoPrint-OAuth2-PGC
 *
 * Author: nils måsén
 * License: AGPLv3
 */
$(function() {
    // function to parse URL
    function parseUrl(url) {
        const parser = document.createElement('a');
        parser.href = url;
        return parser;
    }

    // source: https://stackoverflow.com/questions/105034/create-guid-uuid-in-javascript
    function guid() {
      function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
          .toString(16)
          .substring(1);
      }
      return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
    }

    // source: https://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript
    function getParameterByName(name, url) {
        if (!url) url = window.location.href;
        name = name.replace(/[\[\]]/g, "\\$&");
        var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
            results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, " "));
    }


    function OAuth2PGC_Login_ViewModel(parameters) {
        var self = this;


        $(".dropdown-menu").click(function (e) {
            e.stopPropagation();
        });

        self.loginState = parameters[0];
        self.settings = parameters[1];
        self.control = parameters[2];
        self.access = parameters[3];
        self.coreWizardAcl = parameters[4];

        self.onUserLoggedOut = self.onUserPermissionsChanged = function() {
            // reload if user now lacks STATUS & SETTINGS_READ permissions and is not in first run setup, or is in
            // first run setup but the ACL wizard has already run and ACL is active
            if (!self.loginState.hasAllPermissions(self.access.permissions.STATUS, self.access.permissions.SETTINGS_READ)
                && (!CONFIG_FIRST_RUN || (self.coreWizardAcl
                                          && self.coreWizardAcl.setup()
                                          && self.coreWizardAcl.decision()))) {
                location.reload();
            }
        };

        self.loginState.logout = function() {
            return OctoPrint.browser.logout()
                .done(function(response) {

                    new PNotify({title: gettext("Logout from OctoPrint successful"), text: gettext("You are now logged out"), type: "success"});
                    new PNotify({title: gettext("OAuth 2.0 Logout"), text: gettext("To log out completely, make sure to log out from OAuth 2.0 provider"), hide: false});

                    self.loginState.fromResponse(response);
                })
                .fail(function(error) {
                    if (error && error.status === 401) {
                         self.loginState.fromResponse(false);
                    }
                });
        };



        self.loginState.userMenuText = ko.pureComputed(function () {
           if (self.loginState.loggedIn()){
               return self.loginState.username();
           }
           else {
               return gettext("Login via OAuth 2.0");
           }
        });

    }


    self.onStartup = function () {
        self.elementOAuthLogin = $("#oauth_login");
    };

        /* view model class, parameters for constructor, container to bind to
     * Please see http://docs.octoprint.org/en/master/plugins/viewmodels.html#registering-custom-viewmodels for more details
     * and a full list of the available options.
     */
    OCTOPRINT_VIEWMODELS.push({
        construct: OAuth2PGC_Login_ViewModel,
        // ViewModels your plugin depends on, e.g. loginStateViewModel, settingsViewModel, ...
        dependencies: [ "loginStateViewModel", "settingsViewModel", "controlViewModel", "accessViewModel", "coreWizardAclViewModel" ],
        optional: ["coreWizardAclViewModel"]
        // Elements to bind to, e.g. #settings_plugin_oauth2_pgc, #tab_plugin_oauth2_pgc, ...
        // elements: ["#tab_plugin_oauthfit"]
    });
});
