import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from fastapi import HTTPException, status

import pystache
from mjml import mjml_to_html

from app.settings import (
    EMAIL_NAME,
    EMAIL_ADDRESS,
    EMAIL_PASSWORD,
    EMAIL_HOST,
    EMAIL_PORT,
    FORGOT_PASSWORD_TEMPLATE,
    WELCOME_TEMPLATE,
    APP_URL
)


def verify_file_exists(file_path: str) -> bool:
    """
    Verifies that a file exists.

    Parameters:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file exists, False otherwise.
    """
    try:
        with open(file_path, "rb"):
            pass
    except FileNotFoundError:
        return False
    return True


def send_email(
    recipient_address: str, subject: str, template_path: str, context: dict
) -> None:
    """
    Sends an email to the recipient using the provided template and context.

    Parameters:
        recipient_address (str): The email address of the recipient.
        subject (str): The subject of the email.
        template_path (str): The file path of the email template.
        context (dict): The context data to be used in the email template.

    Returns:
        None
    """

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((EMAIL_NAME, EMAIL_ADDRESS))
    msg["To"] = recipient_address

    if not verify_file_exists(template_path):
        raise FileNotFoundError(
            f"The template file at `{template_path}` does not exist."
        )

    with open(template_path, "rb") as file:
        mail = mjml_to_html(file)

    mail = mail.html
    mail = pystache.render(mail, context)

    msg.set_content(mail, subtype="html")

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

    return None


def send_otp(recipient_address: str, otp: str, subject: str) -> None:
    """
    Sends an email to the user with the OTP.

    Parameters:
        recipient_address (str): The email address of the user.
        otp (str): The OTP to be sent to the user.
        subject (str): The subject of the email.

    Returns:
        None
    """

    context = {
        "verification_code": otp,
    }

    print("Trying to send OTP email")

    send_email(recipient_address, subject, FORGOT_PASSWORD_TEMPLATE, context)

    print("Sent OTP email")

    return None


def send_welcome_mail(recipient_address: str, full_name: str) -> None:
    """
    Sends a welcome email to a new user.

    Parameters:
        recipient_address (str): The email address of the recipient.
        full_name (str): The full name of the sender.

    Returns:
        None
    """

    context = {"full_name": full_name, "link": APP_URL}

    print("Trying to send welcome email")

    try:
        send_email(recipient_address, "Welcome!", WELCOME_TEMPLATE, context)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    print("Sent welcome email")

    return None
