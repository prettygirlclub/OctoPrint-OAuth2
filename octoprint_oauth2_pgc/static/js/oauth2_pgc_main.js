$(function() {
    var OctoPrint = window.OctoPrint;

    OctoPrint.loginui = {
        startedUp: false
    }

    var overlayElement = $("#login-overlay");
    var errorElement = $("#login-error");
    var offlineElement = $("#login-offline");
    var buttonElement = $("#login-button");
    var reconnectElement = $("#login-reconnect");

    buttonElement.click(function() {
        overlayElement.addClass("in");
        errorElement.removeClass("in");
    });

    OctoPrint.options.baseurl = BASE_URL;

    OctoPrint.socket.onConnected = function() {
        buttonElement.prop("disabled", false);
        offlineElement.removeClass("in");
    };

    OctoPrint.socket.onDisconnected = function() {
        buttonElement.prop("disabled", true);
        offlineElement.addClass("in");
    };

    reconnectElement.click(function() {
        OctoPrint.socket.reconnect();
    });

    OctoPrint.socket.connect();
    OctoPrint.loginui.startedUp = true;
});
