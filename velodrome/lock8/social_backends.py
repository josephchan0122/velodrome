from social_core.backends.facebook import FacebookOAuth2
from social_core.backends.google import GoogleOAuth2


class Lock8FacebookOAuth2(FacebookOAuth2):
    name = 'lock8_facebook_oauth2'
    IMAGE_DATA_URL = 'https://graph.facebook.com/v2.3/{0}/picture'
    EXTRA_DATA = FacebookOAuth2.EXTRA_DATA + [
        ('link', 'link', True),
    ]


class Lock8GoogleOAuth2(GoogleOAuth2):
    name = 'lock8_google_oauth2'
    STATE_PARAMETER = False
    EXTRA_DATA = GoogleOAuth2.EXTRA_DATA + [
        ('picture', 'picture', True),
    ]
