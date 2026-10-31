ALLOWED_HOSTS = ["*"]                                                             # EXPECT django-hosts-forwarded
CORS_ALLOW_ALL_ORIGINS = True                                                     # EXPECT cors-reflect-any-origin
CORS_ALLOW_CREDENTIALS = True
SESSION_COOKIE_SECURE = False                                                     # EXPECT cookie-flags-off
