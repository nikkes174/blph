import hashlib
import hmac
import json
import logging
import os
import re
import socket
import secrets
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

load_dotenv()

app = FastAPI()
app.mount('/static', StaticFiles(directory='static'), name='static')
templates = Jinja2Templates(directory='templates')
logger = logging.getLogger('uvicorn.error')

MAX_BODY_BYTES = 32 * 1024
MAX_FIRST_NAME_LEN = 60
MAX_EMAIL_LEN = 120
MAX_PHONE_LEN = 32
MAX_MESSAGE_LEN = 4000
FORM_TOKEN_TTL_SECONDS = 30 * 60
FORM_TOKEN_SECRET = os.getenv('FORM_TOKEN_SECRET') or secrets.token_hex(32)
FAILED_LEADS_PATH = Path(os.getenv('FAILED_LEADS_PATH') or 'data/failed_leads.jsonl')
LEAD_EMAIL_TO = os.getenv('LEAD_EMAIL_TO') or 'pride174@mail.ru'
SMTP_HOST = os.getenv('SMTP_HOST') or 'smtp.mail.ru'
SMTP_PORT = int(os.getenv('SMTP_PORT') or '465')
SMTP_USERNAME = os.getenv('SMTP_USERNAME') or LEAD_EMAIL_TO
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD') or ''
SMTP_USE_SSL = (os.getenv('SMTP_USE_SSL') or 'true').lower() not in ('0', 'false', 'no')
SMTP_TIMEOUT_SECONDS = int(os.getenv('SMTP_TIMEOUT_SECONDS') or '20')

NAME_RE = re.compile(r'^[A-Za-zА-Яа-яЁё\-\s]{1,60}$')
PHONE_RE = re.compile(r'^[0-9+\-\s()]{6,32}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def _make_form_token() -> str:
    ts = int(time.time())
    sig = hmac.new(
        FORM_TOKEN_SECRET.encode('utf-8'),
        str(ts).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return f'{ts}.{sig}'


def _verify_form_token(token: str) -> bool:
    try:
        ts_raw, sig = token.split('.', 1)
        ts = int(ts_raw)
    except Exception:
        return False

    now = int(time.time())
    if ts > now or now - ts > FORM_TOKEN_TTL_SECONDS:
        return False

    expected = hmac.new(
        FORM_TOKEN_SECRET.encode('utf-8'),
        ts_raw.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


@app.get('/')
async def read_index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name='index.html',
        context={'form_token': _make_form_token()},
    )


@app.get('/privacy')
async def read_privacy(request: Request):
    template_path = os.path.join('templates', 'privacy.html')
    if not os.path.exists(template_path):
        return PlainTextResponse('privacy.html not found', status_code=404)
    return templates.TemplateResponse(request=request, name='privacy.html')


def _send_lead_email(first_name: str, email: str, phone: str, message: str) -> tuple[bool, str]:
    if not SMTP_PASSWORD:
        return False, 'Missing SMTP_PASSWORD'

    msg = EmailMessage()
    msg['Subject'] = 'Новая заявка с сайта'
    msg['From'] = SMTP_USERNAME
    msg['To'] = LEAD_EMAIL_TO
    msg['Reply-To'] = email
    msg.set_content(
        '\n'.join([
            'Новая заявка с сайта',
            f'Имя: {first_name}',
            f'Email: {email}',
            f'Телефон: {phone}',
            'Сообщение:',
            message,
        ])
    )

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        return True, ''
    except (TimeoutError, socket.timeout) as exc:
        return False, f'SMTP timeout: {exc}'
    except smtplib.SMTPException as exc:
        return False, f'SMTP error: {exc}'
    except Exception as exc:
        return False, f'Email delivery failed: {exc}'


def _store_failed_lead(payload: dict, error: str) -> None:
    FAILED_LEADS_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        'created_at': int(time.time()),
        'error': error,
        'payload': payload,
    }
    with FAILED_LEADS_PATH.open('a', encoding='utf-8') as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + '\n')


@app.post('/api/lead')
async def create_lead(request: Request):
    def fail(status_code: int, code: str):
        logger.warning('Lead rejected: %s (ip=%s)', code, request.client.host if request.client else '-')
        return JSONResponse({'ok': False, 'error': code}, status_code=status_code)

    content_length = request.headers.get('content-length')
    if content_length:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return fail(413, 'payload_too_large')
        except ValueError:
            return fail(400, 'invalid_content_length')

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return fail(413, 'payload_too_large')

    data: dict = {}
    content_type = request.headers.get('content-type', '').lower()
    if 'application/json' in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
    else:
        try:
            data = dict(await request.form())
        except Exception:
            data = {}

    first_name = (data.get('first_name') or '').strip()
    email = (data.get('email') or '').strip()
    phone = (data.get('phone') or '').strip()
    message = (data.get('message') or '').strip()
    consent = data.get('consent')
    form_token = (data.get('form_token') or '').strip()

    if not first_name or not email or not phone or not message:
        return fail(400, 'required_fields')

    if consent not in (True, 'true', 'on', '1', 1):
        return fail(400, 'consent_required')

    if not form_token or not _verify_form_token(form_token):
        return fail(403, 'invalid_form_token')

    if len(first_name) > MAX_FIRST_NAME_LEN or not NAME_RE.match(first_name):
        return fail(400, 'invalid_first_name')
    if len(email) > MAX_EMAIL_LEN or not EMAIL_RE.match(email):
        return fail(400, 'invalid_email')
    if len(phone) > MAX_PHONE_LEN or not PHONE_RE.match(phone):
        return fail(400, 'invalid_phone')
    if len(message) > MAX_MESSAGE_LEN:
        return fail(400, 'message_too_long')

    ok, err = _send_lead_email(first_name, email, phone, message)
    if not ok:
        logger.error('Lead delivery failed: %s', err)
        _store_failed_lead(
            {
                'first_name': first_name,
                'email': email,
                'phone': phone,
                'message': message,
            },
            err,
        )
        return JSONResponse({'ok': True, 'queued': True})

    return JSONResponse({'ok': True})


if __name__ == '__main__':
    uvicorn.run('main:app', host='127.0.0.1', port=8041, reload=False)
