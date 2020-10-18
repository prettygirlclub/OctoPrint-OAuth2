
def settings_defaults():
    return dict(
        client_id="",
        client_secret="",
        organization="",
        callback_base_url="http://localhost:5000",
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        userinfo_endpoint="https://api.github.com/user",
        orguser_endpoint="https://api.github.com/orgs/{0}/members/{1}",
        username_key="login",
        access_token_query_key="access_token",
        token_headers=dict(Accept="application/json"),
    )
