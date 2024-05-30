from decouple import config

# Import settings from .env file
APP_NAME = "WalletShopAPI"
SECRET_KEY = config("SECRET_KEY")
DB_TYPE = config("DB_TYPE")
DB_NAME = config("DB_NAME")
DB_USER = config("DB_USER")
DB_PASSWORD = config("DB_PASSWORD")
DB_HOST = config("DB_HOST")
DB_PORT = config("DB_PORT")
DB_POOL_SIZE = int(config("DB_POOL_SIZE"))
DB_MAX_OVERFLOW = int(config("DB_MAX_OVERFLOW"))
MYSQL_DRIVER = config("MYSQL_DRIVER")
DATABASE_URL = ""
ALGORITHM = config("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(config("ACCESS_TOKEN_EXPIRE_MINUTES"))
OTP_EXPIRE_MINUTES = int(config("OTP_EXPIRE_MINUTES"))

EMAIL_NAME = config("EMAIL_NAME")
EMAIL_ADDRESS = config("EMAIL_ADDRESS")
EMAIL_PASSWORD = config("EMAIL_PASSWORD")
EMAIL_HOST = config("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT")

WELCOME_TEMPLATE = "templates/email/welcome.mjml"
FORGOT_PASSWORD_TEMPLATE = "templates/email/forgot_password.mjml"
