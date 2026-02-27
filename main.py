import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.request

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


def _send_telegram_message(text: str) -> tuple[bool, str]:
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    if not token or not chat_id:
        return False, 'Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID'

    api_base = (os.getenv('TELEGRAM_API_BASE') or 'https://api.telegram.org').rstrip('/')
    url = f'{api_base}/bot{token}/sendMessage'
    payload = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True,
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    proxy_url = os.getenv('TELEGRAM_PROXY_URL') or os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        if proxy_url
        else urllib.request.ProxyHandler({})
    )
    try:
        with opener.open(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                return True, ''
            return False, f'Telegram API error: {resp.status}'
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode('utf-8', errors='replace')
        except Exception:
            body = '<failed to read body>'
        return False, f'Telegram HTTP error: {exc.code}; body: {body}'
    except Exception as exc:
        return False, f'Telegram request failed: {exc}'


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

    safe_name = html.escape(first_name)
    safe_email = html.escape(email)
    safe_phone = html.escape(phone)
    safe_message = html.escape(message)

    lines = [
        '<b>Новая заявка с сайта</b>',
        f'Имя: {safe_name}',
        f'Email: {safe_email}',
        f'Телефон: {safe_phone}',
        f'Сообщение: {safe_message}',
    ]

    ok, err = _send_telegram_message('\n'.join(lines))
    if not ok:
        logger.error('Lead delivery failed: %s', err)
        return JSONResponse({'ok': False, 'error': err}, status_code=502)

    return JSONResponse({'ok': True})


if __name__ == '__main__':
    uvicorn.run('main:app', host='127.0.0.1', port=8041, reload=False)
