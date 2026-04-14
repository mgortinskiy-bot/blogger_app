import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_reset_email(to_addr: str, reset_url: str) -> tuple[bool, str]:
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587") or "587")
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASS", "").strip()
    mail_from = os.environ.get("MAIL_FROM", user).strip() or user

    if not host or not user:
        return False, "SMTP не настроен (переменные SMTP_HOST, SMTP_USER, SMTP_PASS)"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Проект Хайп — восстановление пароля"
    msg["From"] = mail_from
    msg["To"] = to_addr
    body = (
        f"Здравствуйте!\n\n"
        f"Для сброса пароля перейдите по ссылке (действует ограниченное время):\n{reset_url}\n\n"
        f"Если вы не запрашивали сброс, проигнорируйте письмо.\n"
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(mail_from, [to_addr], msg.as_string())
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
