Vellere
=======

Vellere approximately (in my rather bad Latin), means "they demolish". Specifically, it tells you about a particular category of demolition: Github vulnerability notifications. They are already visible via the Github Web UI, but only to admins, and only to those who both digging through the notifications. Vellere provides a slightly more usable interface, as well as the option for notifying users in Slack, thus encouraging people to maybe actually fix things....

Online version is at [https://vellere.tevp.net/](https://vellere.tevp.net/)

Local install
-------------
1. Install Python
    * (Possibly also make a [Virtualenv](https://virtualenv.pypa.io/en/stable/userguide/#usage))
2. Create a [Github OAuth app](https://github.com/settings/developers) and export the client id/secret as environment variables called `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`
3. Create a [Slack App](https://api.slack.com/apps) and export the client id/secret as environment variables called `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` 
4. `pip install -r requirements.txt`
5. Optional: Setup a database (e.g. Postgres) and export the URL to the database as `DATABASE_URL` using the [dj-database-url URL schema](https://github.com/kennethreitz/dj-database-url#url-schema). If you don't do this, we'll use sqlite by default, which works fine for local dev.
6. Optional: Export `OAUTHLIB_INSECURE_TRANSPORT=1` for local dev without HTTPS
7. `python manage.py migrate`
8. `python manage.py runserver`

[Wharf](https://github.com/palfrey/wharf) install
----------
1. Create a new app called Vellere.
2. Set `GITHUB_URL` to `https://github.com/palfrey/vellere.git`
3. Create a Postgres database
4. Set the Slack/Github environment variables as per local install
5. Deploy the app
6. Configure a usable hostname and enable Let's Encrypt (as OAuth gets unhappy without HTTPS)