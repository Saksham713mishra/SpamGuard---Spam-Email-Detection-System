from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, g
import joblib
import os
import json
import re
import ipaddress
import sqlite3
import secrets
import hashlib
from io import StringIO
from urllib.parse import urlparse, parse_qs, unquote
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from preprocess import TextPreprocessor
from models import SpamDetectionModels
from evaluation import ModelEvaluator
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'emails.csv')
FEEDBACK_EXPORT_PATH = os.path.join(BASE_DIR, 'dataset', 'feedback_retraining.csv')
VECTORIZER_PATH = os.path.join(MODELS_DIR, 'vectorizer.pkl')
MAX_BULK_EMAILS = 500
MAX_SCAN_URLS = 5
MAX_SCAN_TEXT_LENGTH = 12000
DATABASE_PATH = os.path.join(BASE_DIR, 'app_data.db')
SCAN_HISTORY_LIMIT = 100
API_LOG_LIMIT = 200

URL_PATTERN = re.compile(r"((?:https?://|www\.)[^\s<>'\"`]+)", re.IGNORECASE)

URL_RISK_KEYWORDS = [
    'login',
    'verify',
    'secure',
    'update',
    'reset',
    'account',
    'confirm',
    'suspend',
    'gift',
    'prize',
    'bonus',
    'refund',
    'wallet'
]

SUSPICIOUS_URL_TLDS = {
    'zip',
    'top',
    'xyz',
    'click',
    'work',
    'gq',
    'tk',
    'ml',
    'cf'
}

EMAIL_URGENCY_TERMS = [
    'urgent',
    'immediately',
    'action required',
    'verify now',
    'limited time',
    'account suspended',
    'final warning'
]

EMAIL_FINANCIAL_TERMS = [
    'wire transfer',
    'bank details',
    'gift card',
    'crypto',
    'invoice attached',
    'payment failed',
    'refund'
]

SHORTENER_DOMAINS = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'is.gd',
    'rb.gy',
    'cutt.ly'
}

app = Flask(__name__)
app.secret_key = 'replace-this-with-a-secure-key'
app.config['JSON_SORT_KEYS'] = False

# Global variables to store loaded models
models = None
vectorizer = None
evaluator = ModelEvaluator()
all_metrics = None

# Dashboard statistics
dashboard_stats = {
    'total_analyzed': 0,
    'spam_detected': 0,
    'ham_detected': 0,
    'last_prediction': None
}


def _utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


def _get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys = ON;')
    return connection


def _init_database():
    connection = _get_db_connection()
    try:
        connection.executescript(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                input_text TEXT,
                input_url TEXT,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                prediction TEXT,
                top_explanation TEXT,
                super_scan INTEGER NOT NULL DEFAULT 0,
                checked_urls INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_user_created
            ON scan_history(user_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_api_keys_user_created
            ON api_keys(user_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS api_request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                verdict TEXT,
                risk_level TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_api_request_logs_key_created
            ON api_request_logs(api_key_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS scan_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                api_key_id INTEGER,
                scan_history_id INTEGER,
                feedback_label TEXT NOT NULL,
                original_verdict TEXT,
                original_risk_level TEXT,
                original_risk_score INTEGER,
                message_text TEXT,
                source_url TEXT,
                notes TEXT,
                source TEXT NOT NULL DEFAULT 'web_app',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL,
                FOREIGN KEY(scan_history_id) REFERENCES scan_history(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_feedback_created
            ON scan_feedback(created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_scan_feedback_user
            ON scan_feedback(user_id, created_at DESC);
            '''
        )
        connection.commit()
    finally:
        connection.close()


def _get_user_by_id(user_id):
    connection = _get_db_connection()
    try:
        row = connection.execute(
            'SELECT id, username, email, created_at FROM users WHERE id = ?;',
            (user_id,)
        ).fetchone()
        return row
    finally:
        connection.close()


def _get_user_by_identity(identity):
    normalized = (identity or '').strip().lower()
    if not normalized:
        return None

    connection = _get_db_connection()
    try:
        row = connection.execute(
            '''
            SELECT id, username, email, password_hash, created_at
            FROM users
            WHERE lower(username) = ? OR lower(email) = ?;
            ''',
            (normalized, normalized)
        ).fetchone()
        return row
    finally:
        connection.close()


def _create_user(username, email, password):
    now = _utc_now_iso()
    hashed_password = generate_password_hash(password)

    connection = _get_db_connection()
    try:
        cursor = connection.execute(
            '''
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?);
            ''',
            (username, email, hashed_password, now)
        )
        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def _generate_api_key_value():
    return f"sg_{secrets.token_urlsafe(32)}"


def _hash_api_key(raw_key):
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()


def _extract_api_key_from_request():
    auth_header = (request.headers.get('Authorization') or '').strip()
    if auth_header.lower().startswith('bearer '):
        bearer_key = auth_header[7:].strip()
        if bearer_key:
            return bearer_key

    header_key = (request.headers.get('X-API-Key') or '').strip()
    if header_key:
        return header_key

    query_key = (request.args.get('api_key') or '').strip()
    if query_key:
        return query_key

    return None


def _create_api_key(user_id, key_name):
    clean_name = (key_name or '').strip() or 'Default Key'

    for _ in range(5):
        raw_key = _generate_api_key_value()
        key_hash = _hash_api_key(raw_key)
        key_prefix = raw_key[:14]

        connection = _get_db_connection()
        try:
            cursor = connection.execute(
                '''
                INSERT INTO api_keys (
                    user_id,
                    key_name,
                    key_prefix,
                    key_hash,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?);
                ''',
                (int(user_id), clean_name, key_prefix, key_hash, _utc_now_iso())
            )
            connection.commit()
            return {
                'id': int(cursor.lastrowid),
                'raw_key': raw_key,
                'key_name': clean_name,
                'key_prefix': key_prefix
            }
        except sqlite3.IntegrityError:
            continue
        finally:
            connection.close()

    raise RuntimeError('Unable to generate a unique API key. Please retry.')


def _find_active_api_key(raw_key):
    if not raw_key:
        return None

    key_hash = _hash_api_key(raw_key)
    connection = _get_db_connection()
    try:
        row = connection.execute(
            '''
            SELECT
                id,
                user_id,
                key_name,
                key_prefix,
                created_at,
                last_used_at,
                revoked_at
            FROM api_keys
            WHERE key_hash = ? AND revoked_at IS NULL
            LIMIT 1;
            ''',
            (key_hash,)
        ).fetchone()
        return row
    finally:
        connection.close()


def _touch_api_key_last_used(api_key_id):
    connection = _get_db_connection()
    try:
        connection.execute(
            'UPDATE api_keys SET last_used_at = ? WHERE id = ?;',
            (_utc_now_iso(), int(api_key_id))
        )
        connection.commit()
    finally:
        connection.close()


def _log_api_request(api_key_id, endpoint, status_code, verdict=None, risk_level=None):
    connection = _get_db_connection()
    try:
        connection.execute(
            '''
            INSERT INTO api_request_logs (
                api_key_id,
                endpoint,
                status_code,
                verdict,
                risk_level,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?);
            ''',
            (
                int(api_key_id),
                str(endpoint),
                int(status_code),
                str(verdict) if verdict else None,
                str(risk_level) if risk_level else None,
                _utc_now_iso()
            )
        )
        connection.commit()
    finally:
        connection.close()


def _get_user_api_keys(user_id):
    connection = _get_db_connection()
    try:
        rows = connection.execute(
            '''
            SELECT
                k.id,
                k.key_name,
                k.key_prefix,
                k.created_at,
                k.last_used_at,
                k.revoked_at,
                COUNT(l.id) AS usage_count
            FROM api_keys k
            LEFT JOIN api_request_logs l ON l.api_key_id = k.id
            WHERE k.user_id = ?
            GROUP BY k.id, k.key_name, k.key_prefix, k.created_at, k.last_used_at, k.revoked_at
            ORDER BY k.created_at DESC;
            ''',
            (int(user_id),)
        ).fetchall()
        return rows
    finally:
        connection.close()


def _get_user_api_logs(user_id, limit=API_LOG_LIMIT):
    connection = _get_db_connection()
    try:
        rows = connection.execute(
            '''
            SELECT
                l.id,
                l.endpoint,
                l.status_code,
                l.verdict,
                l.risk_level,
                l.created_at,
                k.key_name,
                k.key_prefix
            FROM api_request_logs l
            JOIN api_keys k ON k.id = l.api_key_id
            WHERE k.user_id = ?
            ORDER BY l.created_at DESC
            LIMIT ?;
            ''',
            (int(user_id), int(limit))
        ).fetchall()
        return rows
    finally:
        connection.close()


def _revoke_user_api_key(user_id, key_id):
    connection = _get_db_connection()
    try:
        cursor = connection.execute(
            '''
            UPDATE api_keys
            SET revoked_at = ?
            WHERE id = ? AND user_id = ? AND revoked_at IS NULL;
            ''',
            (_utc_now_iso(), int(key_id), int(user_id))
        )
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()


def _regenerate_user_api_key(user_id, key_id):
    for _ in range(5):
        raw_key = _generate_api_key_value()
        key_hash = _hash_api_key(raw_key)
        key_prefix = raw_key[:14]

        connection = _get_db_connection()
        try:
            cursor = connection.execute(
                '''
                UPDATE api_keys
                SET key_hash = ?, key_prefix = ?, created_at = ?, last_used_at = NULL
                WHERE id = ? AND user_id = ? AND revoked_at IS NULL;
                ''',
                (key_hash, key_prefix, _utc_now_iso(), int(key_id), int(user_id))
            )
            connection.commit()
            if cursor.rowcount > 0:
                return {
                    'raw_key': raw_key,
                    'key_prefix': key_prefix
                }
            return None
        except sqlite3.IntegrityError:
            continue
        finally:
            connection.close()

    raise RuntimeError('Unable to regenerate API key. Please retry.')


def _save_scan_history(user_id, email_text, input_url, response_payload):
    top_explanation = None
    explanations = response_payload.get('explanations')
    if isinstance(explanations, list) and explanations:
        top_explanation = str(explanations[0])

    prediction = response_payload.get('prediction')
    url_analysis = response_payload.get('url_analysis') or {}
    checked_urls = int(url_analysis.get('checked_count', 0) or 0)

    connection = _get_db_connection()
    try:
        cursor = connection.execute(
            '''
            INSERT INTO scan_history (
                user_id,
                input_text,
                input_url,
                verdict,
                risk_score,
                risk_level,
                prediction,
                top_explanation,
                super_scan,
                checked_urls,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''',
            (
                user_id,
                email_text or None,
                input_url or None,
                str(response_payload.get('verdict', 'unknown')),
                int(response_payload.get('risk_score', 0) or 0),
                str(response_payload.get('risk_level', 'low')),
                str(prediction) if prediction is not None else None,
                top_explanation,
                1 if response_payload.get('super_scan') else 0,
                checked_urls,
                _utc_now_iso()
            )
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


def _normalize_feedback_label(raw_label):
    normalized = (raw_label or '').strip().lower().replace('-', '_').replace(' ', '_')
    if normalized in {'safe', 'ham', 'not_spam', 'legit', 'false_positive'}:
        return 'safe'
    if normalized in {'scam', 'spam', 'phishing', 'unsafe', 'malicious'}:
        return 'scam'
    return None


def _save_feedback_entry(
    feedback_label,
    message_text=None,
    source_url=None,
    original_verdict=None,
    original_risk_level=None,
    original_risk_score=None,
    source='web_app',
    notes=None,
    user_id=None,
    api_key_id=None,
    scan_history_id=None
):
    clean_label = _normalize_feedback_label(feedback_label)
    if clean_label is None:
        raise ValueError('feedback_label must be safe/ham or scam/spam/phishing.')

    clean_message_text = (message_text or '').strip()[:12000]
    clean_source_url = (source_url or '').strip()[:2048]
    clean_notes = (notes or '').strip()[:400]
    clean_source = (source or 'web_app').strip().lower()[:60]

    clean_score = None
    try:
        if original_risk_score is not None and str(original_risk_score).strip() != '':
            clean_score = int(original_risk_score)
    except (ValueError, TypeError):
        clean_score = None

    connection = _get_db_connection()
    try:
        cursor = connection.execute(
            '''
            INSERT INTO scan_feedback (
                user_id,
                api_key_id,
                scan_history_id,
                feedback_label,
                original_verdict,
                original_risk_level,
                original_risk_score,
                message_text,
                source_url,
                notes,
                source,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            ''',
            (
                int(user_id) if user_id is not None else None,
                int(api_key_id) if api_key_id is not None else None,
                int(scan_history_id) if scan_history_id is not None else None,
                clean_label,
                str(original_verdict) if original_verdict else None,
                str(original_risk_level) if original_risk_level else None,
                clean_score,
                clean_message_text or None,
                clean_source_url or None,
                clean_notes or None,
                clean_source,
                _utc_now_iso()
            )
        )
        connection.commit()
        return int(cursor.lastrowid), clean_label
    finally:
        connection.close()


def _get_feedback_summary(user_id=None):
    filters = ''
    params = []
    if user_id is not None:
        filters = 'WHERE user_id = ?'
        params.append(int(user_id))

    connection = _get_db_connection()
    try:
        total = connection.execute(
            f'SELECT COUNT(*) AS total_count FROM scan_feedback {filters};',
            tuple(params)
        ).fetchone()['total_count']

        scam = connection.execute(
            f"SELECT COUNT(*) AS scam_count FROM scan_feedback {filters + (' AND' if filters else ' WHERE')} feedback_label = 'scam';",
            tuple(params)
        ).fetchone()['scam_count']

        safe = connection.execute(
            f"SELECT COUNT(*) AS safe_count FROM scan_feedback {filters + (' AND' if filters else ' WHERE')} feedback_label = 'safe';",
            tuple(params)
        ).fetchone()['safe_count']

        retrain_ready = connection.execute(
            f"SELECT COUNT(*) AS retrain_ready_count FROM scan_feedback {filters + (' AND' if filters else ' WHERE')} message_text IS NOT NULL AND trim(message_text) != '';",
            tuple(params)
        ).fetchone()['retrain_ready_count']

        return {
            'total_count': int(total or 0),
            'scam_count': int(scam or 0),
            'safe_count': int(safe or 0),
            'retrain_ready_count': int(retrain_ready or 0)
        }
    finally:
        connection.close()


def _export_feedback_dataset(output_path=FEEDBACK_EXPORT_PATH):
    connection = _get_db_connection()
    try:
        rows = connection.execute(
            '''
            SELECT message_text, feedback_label, source, created_at
            FROM scan_feedback
            WHERE message_text IS NOT NULL AND trim(message_text) != ''
            ORDER BY created_at DESC;
            '''
        ).fetchall()
    finally:
        connection.close()

    records = []
    for row in rows:
        label = 'spam' if row['feedback_label'] == 'scam' else 'ham'
        records.append({
            'email_text': row['message_text'],
            'label': label,
            'source': row['source'] or 'feedback',
            'created_at': row['created_at']
        })

    export_df = pd.DataFrame(records, columns=['email_text', 'label', 'source', 'created_at'])
    if not export_df.empty:
        export_df = export_df.drop_duplicates(subset=['email_text', 'label']).reset_index(drop=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    export_df.to_csv(output_path, index=False)
    return {
        'exported_count': int(len(export_df)),
        'output_path': output_path
    }


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if g.current_user is None:
            flash('Please sign in to access this page.', 'warning')
            return redirect(url_for('login', next=request.path))
        return view_function(*args, **kwargs)

    return wrapped_view


@app.before_request
def _load_current_user():
    user_id = session.get('user_id')
    g.current_user = _get_user_by_id(user_id) if user_id else None


_init_database()


def _clamp_score(score):
    return max(0, min(100, int(round(score))))


def _risk_level_from_score(score):
    if score >= 70:
        return 'high'
    if score >= 40:
        return 'medium'
    return 'low'


def _update_dashboard_stats(result_label, preview_text):
    if result_label not in ['spam', 'ham']:
        return

    dashboard_stats['total_analyzed'] += 1
    if result_label == 'spam':
        dashboard_stats['spam_detected'] += 1
    else:
        dashboard_stats['ham_detected'] += 1

    preview_text = preview_text.strip() if isinstance(preview_text, str) else ''
    dashboard_stats['last_prediction'] = {
        'result': result_label,
        'email_preview': preview_text[:100] + ('...' if len(preview_text) > 100 else '')
    }


def _extract_urls_from_text(text, max_urls=MAX_SCAN_URLS):
    if not isinstance(text, str) or not text.strip():
        return []

    urls = []
    seen = set()
    for raw_match in URL_PATTERN.findall(text):
        candidate = raw_match.strip().strip('.,);]>\"\'')
        if candidate.lower().startswith('www.'):
            candidate = f'https://{candidate}'

        dedupe_key = candidate.lower()
        if dedupe_key and dedupe_key not in seen:
            seen.add(dedupe_key)
            urls.append(candidate)

        if len(urls) >= max_urls:
            break

    return urls


def _normalize_url_candidate(raw_url):
    if not isinstance(raw_url, str):
        return '', None

    candidate = raw_url.strip()
    if not candidate:
        return '', None

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', candidate):
        candidate = f'https://{candidate}'

    parsed = urlparse(candidate)
    if not parsed.netloc:
        return candidate, None

    return candidate, parsed


def _analyze_url_signals(raw_url):
    normalized_url, parsed = _normalize_url_candidate(raw_url)
    if parsed is None:
        return {
            'input_url': raw_url,
            'normalized_url': normalized_url or raw_url,
            'is_valid': False,
            'risk_score': 60,
            'risk_level': 'medium',
            'reasons': ['Invalid URL format or missing hostname.'],
            'signals': {}
        }

    score = 0
    reasons = []

    host_with_port = (parsed.netloc or '').split('@')[-1]
    host = host_with_port.split(':')[0].lower()
    if not host:
        return {
            'input_url': raw_url,
            'normalized_url': normalized_url,
            'is_valid': False,
            'risk_score': 60,
            'risk_level': 'medium',
            'reasons': ['URL does not contain a valid host.'],
            'signals': {}
        }

    if parsed.scheme.lower() != 'https':
        score += 12
        reasons.append('URL does not use HTTPS.')

    uses_ip_host = False
    try:
        ipaddress.ip_address(host)
        uses_ip_host = True
    except ValueError:
        uses_ip_host = False

    if uses_ip_host:
        score += 25
        reasons.append('Domain is an IP address, commonly used in phishing links.')

    labels = [label for label in host.split('.') if label]
    tld = labels[-1] if labels else ''

    if host.startswith('xn--') or '.xn--' in host:
        score += 18
        reasons.append('Punycode domain detected; this can hide lookalike characters.')

    if len(labels) >= 4:
        score += 10
        reasons.append('Domain contains many subdomains, which can indicate obfuscation.')

    if tld in SUSPICIOUS_URL_TLDS:
        score += 15
        reasons.append(f'Uses high-risk top-level domain: .{tld}.')

    if len(host) > 35:
        score += 7
        reasons.append('Domain is unusually long.')

    decoded_url = unquote(normalized_url.lower())
    keyword_hits = [term for term in URL_RISK_KEYWORDS if term in decoded_url]
    if keyword_hits:
        score += min(24, len(keyword_hits) * 4)
        reasons.append(f"Contains risky URL terms: {', '.join(keyword_hits[:4])}.")

    if '@' in normalized_url:
        score += 10
        reasons.append('URL contains @ symbol, a common redirect obfuscation trick.')

    if normalized_url.count('%') > 3:
        score += 6
        reasons.append('URL has heavy percent-encoding.')

    if len(normalized_url) > 120:
        score += 6
        reasons.append('URL is very long and may hide malicious payloads.')

    query_params = parse_qs(parsed.query)
    risky_params = [
        name for name in query_params
        if name.lower() in {'redirect', 'url', 'next', 'continue', 'token', 'session', 'login', 'password'}
    ]
    if risky_params:
        score += 8
        reasons.append(f"Sensitive query parameters detected: {', '.join(risky_params[:3])}.")

    path_depth = len([segment for segment in parsed.path.split('/') if segment])
    if path_depth >= 5:
        score += 5
        reasons.append('URL path depth is unusually high.')

    if not reasons:
        reasons.append('No obvious URL red flags were found.')

    final_score = _clamp_score(score)
    return {
        'input_url': raw_url,
        'normalized_url': normalized_url,
        'is_valid': True,
        'risk_score': final_score,
        'risk_level': _risk_level_from_score(final_score),
        'reasons': reasons,
        'signals': {
            'host': host,
            'scheme': parsed.scheme,
            'uses_ip_host': uses_ip_host,
            'keyword_hits': keyword_hits[:6],
            'path_depth': path_depth
        }
    }


def _analyze_email_signals(email_text, model_result=None):
    lowered = email_text.lower()
    score = 0
    reasons = []
    prediction = None
    model_votes = {}
    model_status = 'heuristic-only'

    if isinstance(model_result, dict) and not model_result.get('error'):
        prediction = model_result.get('prediction')
        model_votes = model_result.get('individual_predictions') or {}
        model_status = 'available'

        if prediction == 'spam':
            score += 45
            reasons.append('ML classifier flagged this text as spam.')
        elif prediction == 'ham':
            score += 8
            reasons.append('ML classifier marked this text as likely safe.')
    elif isinstance(model_result, dict) and model_result.get('error'):
        model_status = 'unavailable'
        reasons.append('ML classifier unavailable; fallback heuristic signals were used.')

    urgency_hits = [term for term in EMAIL_URGENCY_TERMS if term in lowered]
    if urgency_hits:
        score += min(18, len(urgency_hits) * 4)
        reasons.append(f"Urgency language detected: {', '.join(urgency_hits[:3])}.")

    financial_hits = [term for term in EMAIL_FINANCIAL_TERMS if term in lowered]
    if financial_hits:
        score += min(20, len(financial_hits) * 4)
        reasons.append(f"Financial bait terms detected: {', '.join(financial_hits[:3])}.")

    exclamations = email_text.count('!')
    if exclamations >= 3:
        score += 6
        reasons.append('Message contains excessive exclamation marks.')

    uppercase_tokens = re.findall(r'\b[A-Z]{4,}\b', email_text)
    if len(uppercase_tokens) >= 2:
        score += 7
        reasons.append('Contains multiple all-caps words.')

    embedded_urls = _extract_urls_from_text(email_text, max_urls=MAX_SCAN_URLS)
    if embedded_urls:
        score += min(12, 4 + len(embedded_urls) * 2)
        reasons.append(f'Contains {len(embedded_urls)} embedded URL(s).')

        found_shortener = False
        for candidate_url in embedded_urls:
            _, parsed_url = _normalize_url_candidate(candidate_url)
            if parsed_url is None:
                continue

            host = (parsed_url.netloc or '').split('@')[-1].split(':')[0].lower()
            if host in SHORTENER_DOMAINS:
                found_shortener = True
                break

        if found_shortener:
            score += 8
            reasons.append('Uses a URL shortener, which is common in phishing campaigns.')

    if len(email_text) < 40:
        score += 4
        reasons.append('Message is very short and lacks contextual detail.')

    if not reasons:
        reasons.append('No major spam indicators were found in text content.')

    final_score = _clamp_score(score)
    return {
        'prediction': prediction,
        'model_status': model_status,
        'individual_predictions': model_votes,
        'risk_score': final_score,
        'risk_level': _risk_level_from_score(final_score),
        'reasons': reasons[:8],
        'detected_urls': embedded_urls
    }


def _recommend_scan_actions(level, has_url):
    if level == 'high':
        actions = [
            'Do not click links or download attachments from this message.',
            'Verify the sender or brand through an official contact channel.',
            'Report and quarantine this message in your mailbox.'
        ]
        if has_url:
            actions.append('Run additional domain reputation checks before visiting the URL.')
        return actions

    if level == 'medium':
        actions = [
            'Treat this message as suspicious until verified.',
            'Check the sender domain and request details independently.',
            'Avoid sharing passwords, OTPs, or payment details.'
        ]
        if has_url:
            actions.append('Open the URL only after manual verification of the domain.')
        return actions

    actions = [
        'No strong threat signals detected, but remain cautious.',
        'Continue standard security hygiene before sharing sensitive data.'
    ]
    if has_url:
        actions.append('Confirm the URL domain still matches the expected organization.')
    return actions


def _compose_scan_verdict(email_analysis, url_reports, super_scan):
    email_score = email_analysis.get('risk_score', 0) if email_analysis else 0
    url_score = max((item.get('risk_score', 0) for item in url_reports), default=0)

    if email_analysis and url_reports:
        combined_score = max(email_score, url_score) + int(round(min(email_score, url_score) * 0.35))
    else:
        combined_score = email_score or url_score

    if super_scan and len(url_reports) > 1:
        combined_score += min(10, len(url_reports) * 2)

    if email_analysis and email_analysis.get('prediction') == 'spam' and url_score >= 50:
        combined_score += 10

    combined_score = _clamp_score(combined_score)
    combined_level = _risk_level_from_score(combined_score)

    top_risky_url = None
    if url_reports:
        top_risky_url = max(url_reports, key=lambda item: item.get('risk_score', 0))

    combined_reasons = []
    if email_analysis:
        combined_reasons.extend(email_analysis.get('reasons', []))
    if top_risky_url:
        combined_reasons.extend(top_risky_url.get('reasons', []))

    unique_reasons = []
    seen = set()
    for reason in combined_reasons:
        normalized_reason = reason.strip().lower()
        if normalized_reason and normalized_reason not in seen:
            seen.add(normalized_reason)
            unique_reasons.append(reason)

    if combined_score >= 70:
        verdict = 'likely_scam'
    elif combined_score >= 40:
        verdict = 'suspicious'
    else:
        verdict = 'likely_safe'

    return {
        'verdict': verdict,
        'risk_score': combined_score,
        'risk_level': combined_level,
        'explanations': unique_reasons[:8],
        'recommendations': _recommend_scan_actions(combined_level, bool(url_reports)),
        'top_risky_url': top_risky_url
    }

def load_model():
    """
    Load trained models and vectorizer from disk.
    """
    global models, vectorizer, all_metrics

    try:
        models = SpamDetectionModels()
        models.load_models(MODELS_DIR)
        vectorizer = joblib.load(VECTORIZER_PATH)

        metrics_path = os.path.join(MODELS_DIR, 'metrics.json')
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r', encoding='utf-8') as metrics_file:
                all_metrics = json.load(metrics_file)
        else:
            all_metrics = None

        print("Models and vectorizer loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading models: {e}")
        return False


def _normalize_bulk_inputs(items):
    """Normalize mixed input payloads into clean email text list."""
    normalized = []
    for item in items:
        text = None

        if isinstance(item, str):
            text = item
        elif isinstance(item, dict):
            for key in ['email_text', 'text', 'message', 'body', 'content']:
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    text = value
                    break

        if isinstance(text, str):
            cleaned = text.strip()
            if cleaned:
                normalized.append(cleaned)

    return normalized


def _extract_emails_from_file(uploaded_file):
    """Extract email lines from uploaded CSV or TXT file."""
    filename = (uploaded_file.filename or '').lower()
    raw_bytes = uploaded_file.read()

    if not raw_bytes:
        return [], 'Uploaded file is empty.'

    try:
        content = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        content = raw_bytes.decode('latin-1', errors='ignore')

    if filename.endswith('.txt'):
        emails = [line.strip() for line in content.splitlines() if line.strip()]
        return emails, None

    if filename.endswith('.csv'):
        try:
            dataframe = pd.read_csv(StringIO(content))
        except Exception:
            return [], 'Could not parse CSV file. Please upload a valid CSV.'

        if dataframe.empty:
            return [], 'Uploaded CSV is empty.'

        normalized_columns = {str(col).strip().lower(): col for col in dataframe.columns}
        source_column = None
        for column_name in ['email_text', 'text', 'message', 'body', 'content']:
            if column_name in normalized_columns:
                source_column = normalized_columns[column_name]
                break

        if source_column is None:
            source_column = dataframe.columns[0]

        emails = [
            value.strip()
            for value in dataframe[source_column].fillna('').astype(str).tolist()
            if value and value.strip()
        ]
        return emails, None

    return [], 'Only .csv and .txt files are supported for bulk upload.'


def _predict_bulk_emails(email_texts):
    """Run batch predictions and build aggregate summary."""
    results = []
    spam_count = 0
    ham_count = 0
    failed_count = 0

    for idx, email_text in enumerate(email_texts, start=1):
        prediction_result = predict_email(email_text, update_stats=False)

        if prediction_result.get('error'):
            failed_count += 1
            results.append({
                'index': idx,
                'email_preview': email_text[:140] + ('...' if len(email_text) > 140 else ''),
                'error': prediction_result['error']
            })
            continue

        if prediction_result['prediction'] == 'spam':
            spam_count += 1
        else:
            ham_count += 1

        results.append({
            'index': idx,
            'email_text': email_text,
            'email_preview': email_text[:140] + ('...' if len(email_text) > 140 else ''),
            'prediction': prediction_result['prediction']
        })

    processed_count = spam_count + ham_count
    if processed_count > 0:
        dashboard_stats['total_analyzed'] += processed_count
        dashboard_stats['spam_detected'] += spam_count
        dashboard_stats['ham_detected'] += ham_count

        last_valid_result = next(
            (item for item in reversed(results) if item.get('prediction') in ['spam', 'ham']),
            None
        )
        if last_valid_result:
            dashboard_stats['last_prediction'] = {
                'result': last_valid_result['prediction'],
                'email_preview': last_valid_result['email_preview']
            }

    return {
        'summary': {
            'total': len(email_texts),
            'processed': processed_count,
            'spam': spam_count,
            'ham': ham_count,
            'failed': failed_count
        },
        'results': results
    }

@app.route('/predict', methods=['POST'])
def predict_route():
    """API endpoint to classify email content as spam or ham."""
    request_data = request.get_json(silent=True)
    if not request_data:
        return jsonify(error="Request body must be JSON with an 'email_text' field."), 400

    email_text = request_data.get('email_text')
    if not email_text or not isinstance(email_text, str):
        return jsonify(error="Please provide non-empty email_text for prediction."), 400

    if models is None or vectorizer is None:
        loaded = load_model()
        if not loaded:
            return jsonify(error="Model resources are unavailable. Please ensure models are trained and saved in the 'models/' directory."), 500

    result = predict_email(email_text)
    if result.get('error'):
        return jsonify(result), 200

    return jsonify(result), 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if g.current_user is not None:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'warning')
        elif not email or '@' not in email:
            flash('Please provide a valid email address.', 'warning')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long.', 'warning')
        elif password != confirm_password:
            flash('Password and confirmation do not match.', 'warning')
        else:
            try:
                _create_user(username=username, email=email, password=password)
                flash('Account created successfully. Please sign in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username or email already exists. Try another one.', 'warning')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if g.current_user is not None:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        identity = (request.form.get('identity') or '').strip()
        password = request.form.get('password') or ''

        if not identity or not password:
            flash('Please provide username/email and password.', 'warning')
        else:
            user = _get_user_by_identity(identity)
            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = int(user['id'])
                flash('Signed in successfully.', 'success')

                next_path = request.args.get('next')
                if next_path and next_path.startswith('/'):
                    return redirect(next_path)

                return redirect(url_for('dashboard'))

            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    """User logout route."""
    session.clear()
    flash('You have been signed out.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/history')
@login_required
def history():
    """Display authenticated user's scan history."""
    connection = _get_db_connection()
    try:
        rows = connection.execute(
            '''
            SELECT
                id,
                input_text,
                input_url,
                verdict,
                risk_score,
                risk_level,
                prediction,
                top_explanation,
                super_scan,
                checked_urls,
                created_at
            FROM scan_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?;
            ''',
            (int(g.current_user['id']), SCAN_HISTORY_LIMIT)
        ).fetchall()
    finally:
        connection.close()

    return render_template('history.html', history_rows=rows)


@app.route('/developer')
@login_required
def developer_dashboard():
    """Developer dashboard for API key management and usage logs."""
    user_id = int(g.current_user['id'])
    api_keys = _get_user_api_keys(user_id)
    api_logs = _get_user_api_logs(user_id)
    feedback_summary = _get_feedback_summary(user_id=None)

    generated_api_key = session.pop('generated_api_key', None)
    generated_api_key_name = session.pop('generated_api_key_name', None)

    return render_template(
        'developer.html',
        api_keys=api_keys,
        api_logs=api_logs,
        feedback_summary=feedback_summary,
        generated_api_key=generated_api_key,
        generated_api_key_name=generated_api_key_name
    )


@app.route('/developer/keys/create', methods=['POST'])
@login_required
def create_api_key_route():
    """Create a new API key for the authenticated user."""
    key_name = (request.form.get('key_name') or '').strip()
    if len(key_name) > 60:
        key_name = key_name[:60]

    try:
        key_data = _create_api_key(user_id=int(g.current_user['id']), key_name=key_name)
    except RuntimeError as key_error:
        flash(str(key_error), 'danger')
        return redirect(url_for('developer_dashboard'))

    session['generated_api_key'] = key_data['raw_key']
    session['generated_api_key_name'] = key_data['key_name']
    flash('API key created. Copy it now; this value is shown only once.', 'success')
    return redirect(url_for('developer_dashboard'))


@app.route('/developer/keys/<int:key_id>/revoke', methods=['POST'])
@login_required
def revoke_api_key_route(key_id):
    """Revoke an existing API key belonging to the authenticated user."""
    revoked = _revoke_user_api_key(user_id=int(g.current_user['id']), key_id=key_id)
    if revoked:
        flash('API key revoked successfully.', 'info')
    else:
        flash('API key not found or already revoked.', 'warning')
    return redirect(url_for('developer_dashboard'))


@app.route('/developer/keys/<int:key_id>/regenerate', methods=['POST'])
@login_required
def regenerate_api_key_route(key_id):
    """Regenerate an active API key and return a new one-time visible value."""
    try:
        key_data = _regenerate_user_api_key(user_id=int(g.current_user['id']), key_id=key_id)
    except RuntimeError as key_error:
        flash(str(key_error), 'danger')
        return redirect(url_for('developer_dashboard'))

    if key_data is None:
        flash('API key not found or already revoked.', 'warning')
        return redirect(url_for('developer_dashboard'))

    session['generated_api_key'] = key_data['raw_key']
    session['generated_api_key_name'] = 'Regenerated Key'
    flash('API key regenerated. Copy it now; old key no longer works.', 'success')
    return redirect(url_for('developer_dashboard'))


@app.route('/developer/feedback/export', methods=['POST'])
@login_required
def export_feedback_dataset_route():
    """Export accumulated feedback to retraining CSV dataset."""
    export_result = _export_feedback_dataset(output_path=FEEDBACK_EXPORT_PATH)
    flash(
        f"Feedback dataset exported: {export_result['exported_count']} rows to {export_result['output_path']}",
        'success'
    )
    return redirect(url_for('developer_dashboard'))


@app.route('/feedback', methods=['POST'])
def feedback_route():
    """Capture user feedback for model improvement and retraining loop."""
    request_api_key = _extract_api_key_from_request()
    api_key_record = None

    if request_api_key:
        api_key_record = _find_active_api_key(request_api_key)
        if api_key_record is None:
            return jsonify(error='Invalid or revoked API key.'), 401
        _touch_api_key_last_used(api_key_record['id'])

    if g.current_user is not None and api_key_record is not None:
        if int(g.current_user['id']) != int(api_key_record['user_id']):
            return jsonify(error='API key does not belong to the signed-in user.'), 403

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify(error='Request body must be JSON.'), 400

    feedback_label = payload.get('feedback_label')
    message_text = payload.get('email_text') or payload.get('message_text') or payload.get('text')
    source_url = payload.get('url') or payload.get('source_url') or payload.get('website_url')
    source = payload.get('source') or 'web_app'
    notes = payload.get('notes')
    scan_history_id = payload.get('scan_history_id')

    original_scan = payload.get('original_scan') if isinstance(payload.get('original_scan'), dict) else {}
    original_verdict = payload.get('original_verdict') or original_scan.get('verdict')
    original_risk_level = payload.get('original_risk_level') or original_scan.get('risk_level')
    original_risk_score = payload.get('original_risk_score')
    if original_risk_score is None:
        original_risk_score = original_scan.get('risk_score')

    acting_user_id = None
    if g.current_user is not None:
        acting_user_id = int(g.current_user['id'])
    elif api_key_record is not None:
        acting_user_id = int(api_key_record['user_id'])

    try:
        feedback_id, normalized_label = _save_feedback_entry(
            feedback_label=feedback_label,
            message_text=message_text,
            source_url=source_url,
            original_verdict=original_verdict,
            original_risk_level=original_risk_level,
            original_risk_score=original_risk_score,
            source=source,
            notes=notes,
            user_id=acting_user_id,
            api_key_id=int(api_key_record['id']) if api_key_record is not None else None,
            scan_history_id=scan_history_id
        )
    except ValueError as feedback_error:
        if api_key_record is not None:
            _log_api_request(int(api_key_record['id']), '/feedback', 400)
        return jsonify(error=str(feedback_error)), 400
    except Exception as feedback_error:
        print(f'Failed to save feedback: {feedback_error}')
        if api_key_record is not None:
            _log_api_request(int(api_key_record['id']), '/feedback', 500)
        return jsonify(error='Failed to save feedback.'), 500

    if api_key_record is not None:
        _log_api_request(int(api_key_record['id']), '/feedback', 200)

    return jsonify(
        {
            'status': 'ok',
            'feedback_id': feedback_id,
            'feedback_label': normalized_label,
            'authenticated_via': (
                'api_key' if api_key_record is not None else ('session' if g.current_user is not None else 'anonymous')
            )
        }
    ), 200


@app.route('/scan', methods=['POST'])
def scan_route():
    """Unified scan endpoint for email text and suspicious URL analysis."""
    request_api_key = _extract_api_key_from_request()
    api_key_record = None

    if request_api_key:
        api_key_record = _find_active_api_key(request_api_key)
        if api_key_record is None:
            return jsonify(error='Invalid or revoked API key.'), 401
        _touch_api_key_last_used(api_key_record['id'])

    if g.current_user is not None and api_key_record is not None:
        if int(g.current_user['id']) != int(api_key_record['user_id']):
            return jsonify(error='API key does not belong to the signed-in user.'), 403

    def _build_scan_response(payload, status_code):
        if api_key_record is not None:
            try:
                _log_api_request(
                    api_key_id=int(api_key_record['id']),
                    endpoint='/scan',
                    status_code=status_code,
                    verdict=payload.get('verdict') if isinstance(payload, dict) else None,
                    risk_level=payload.get('risk_level') if isinstance(payload, dict) else None
                )
            except Exception as log_error:
                print(f'Failed to log API key request: {log_error}')

        return jsonify(payload), status_code

    request_data = request.get_json(silent=True)
    if not request_data:
        return _build_scan_response(
            {'error': "Request body must be JSON with email_text/message_text and/or url fields."},
            400
        )

    email_text = request_data.get('email_text')
    if email_text is None:
        email_text = request_data.get('message_text')

    url = request_data.get('url')
    if url is None:
        url = request_data.get('website_url')

    if email_text is not None and not isinstance(email_text, str):
        return _build_scan_response({'error': 'email_text must be a string when provided.'}, 400)

    if url is not None and not isinstance(url, str):
        return _build_scan_response({'error': 'url must be a string when provided.'}, 400)

    super_scan = bool(request_data.get('super_scan', False))
    email_text = (email_text or '').strip()
    url = (url or '').strip()

    if not email_text and not url:
        return _build_scan_response(
            {'error': 'Provide at least one input: email_text/message_text or url.'},
            400
        )

    if len(email_text) > MAX_SCAN_TEXT_LENGTH:
        return _build_scan_response(
            {'error': f'email_text exceeds maximum length of {MAX_SCAN_TEXT_LENGTH} characters.'},
            400
        )

    model_result = None
    if email_text:
        if models is None or vectorizer is None:
            load_model()

        if models is not None and vectorizer is not None:
            model_result = predict_email(email_text, update_stats=False)
        else:
            model_result = {'error': 'Model resources unavailable for ML classification.'}

    email_analysis = _analyze_email_signals(email_text, model_result) if email_text else None

    urls_to_scan = []
    if url:
        urls_to_scan.append(url)

    extracted_urls = _extract_urls_from_text(email_text, max_urls=MAX_SCAN_URLS) if email_text else []
    if extracted_urls:
        if super_scan:
            urls_to_scan.extend(extracted_urls)
        elif not urls_to_scan:
            urls_to_scan.append(extracted_urls[0])

    deduped_urls = []
    seen_urls = set()
    for candidate_url in urls_to_scan:
        cleaned_url = candidate_url.strip()
        dedupe_key = cleaned_url.lower()
        if cleaned_url and dedupe_key not in seen_urls:
            seen_urls.add(dedupe_key)
            deduped_urls.append(cleaned_url)

    url_reports = [_analyze_url_signals(candidate_url) for candidate_url in deduped_urls]
    verdict_payload = _compose_scan_verdict(email_analysis, url_reports, super_scan)

    if email_analysis and email_analysis.get('prediction') in ['spam', 'ham']:
        _update_dashboard_stats(email_analysis['prediction'], email_text)

    acting_user_id = None
    if g.current_user is not None:
        acting_user_id = int(g.current_user['id'])
    elif api_key_record is not None:
        acting_user_id = int(api_key_record['user_id'])

    response_payload = {
        'verdict': verdict_payload['verdict'],
        'risk_score': verdict_payload['risk_score'],
        'risk_level': verdict_payload['risk_level'],
        'explanations': verdict_payload['explanations'],
        'recommendations': verdict_payload['recommendations'],
        'super_scan': super_scan,
        'email_analysis': email_analysis,
        'url_analysis': {
            'checked_count': len(url_reports),
            'urls': url_reports,
            'top_risky_url': verdict_payload['top_risky_url']
        }
    }

    if email_analysis and email_analysis.get('prediction'):
        response_payload['prediction'] = email_analysis['prediction']

    history_saved = False
    saved_scan_id = None
    if acting_user_id is not None:
        try:
            saved_scan_id = _save_scan_history(
                user_id=acting_user_id,
                email_text=email_text,
                input_url=url,
                response_payload=response_payload
            )
            history_saved = True
        except Exception as save_error:
            print(f'Failed to save scan history: {save_error}')

    response_payload['history_saved'] = history_saved
    response_payload['scan_history_id'] = saved_scan_id
    response_payload['authenticated_via'] = (
        'api_key' if api_key_record is not None else ('session' if g.current_user is not None else 'anonymous')
    )

    return _build_scan_response(response_payload, 200)


@app.route('/predict/bulk', methods=['POST'])
def predict_bulk_route():
    """API endpoint for bulk JSON predictions."""
    request_data = request.get_json(silent=True)
    if not request_data or not isinstance(request_data.get('emails'), list):
        return jsonify(error="Request body must include an 'emails' list."), 400

    email_texts = _normalize_bulk_inputs(request_data['emails'])
    if not email_texts:
        return jsonify(error='No valid email_text values found in request.'), 400

    if len(email_texts) > MAX_BULK_EMAILS:
        return jsonify(error=f'Maximum {MAX_BULK_EMAILS} emails allowed per request.'), 400

    if models is None or vectorizer is None:
        loaded = load_model()
        if not loaded:
            return jsonify(error="Model resources are unavailable. Please ensure models are trained and saved in the 'models/' directory."), 500

    return jsonify(_predict_bulk_emails(email_texts)), 200


@app.route('/predict/bulk-upload', methods=['POST'])
def predict_bulk_upload_route():
    """API endpoint for bulk file upload predictions (.csv/.txt)."""
    uploaded_file = request.files.get('file')
    if uploaded_file is None or not uploaded_file.filename:
        return jsonify(error='Please upload a CSV or TXT file in the file field.'), 400

    email_texts, extraction_error = _extract_emails_from_file(uploaded_file)
    if extraction_error:
        return jsonify(error=extraction_error), 400

    if not email_texts:
        return jsonify(error='No valid email text rows found in uploaded file.'), 400

    if len(email_texts) > MAX_BULK_EMAILS:
        return jsonify(error=f'Maximum {MAX_BULK_EMAILS} emails allowed per upload.'), 400

    if models is None or vectorizer is None:
        loaded = load_model()
        if not loaded:
            return jsonify(error="Model resources are unavailable. Please ensure models are trained and saved in the 'models/' directory."), 500

    payload = _predict_bulk_emails(email_texts)
    payload['source_file'] = uploaded_file.filename
    return jsonify(payload), 200

def train_model():
    """
    Train the models using the training script.
    """
    try:
        # Import and run training
        from train import train_and_evaluate
        global models, vectorizer, all_metrics

        models, vectorizer, all_metrics = train_and_evaluate(data_path=DATASET_PATH)
        return True
    except Exception as e:
        print(f"Error training models: {e}")
        return False

def predict_email(email_text, update_stats=True):
    """
    Predict if an email is spam or ham.

    Args:
        email_text (str): Email content to classify

    Returns:
        dict: Prediction result
    """
    if models is None or vectorizer is None:
        return {"error": "Models not loaded. Please train the models first."}

    try:
        # Preprocess the email
        preprocessor = TextPreprocessor()
        processed_text = preprocessor.preprocess_text(email_text)

        # Extract features
        features = vectorizer.transform([processed_text])

        # Make prediction
        prediction = int(models.predict(features)[0])
        result = "spam" if prediction == 1 else "ham"

        # Update dashboard statistics
        if update_stats:
            _update_dashboard_stats(result, email_text)

        # Get individual model predictions for comparison
        individual_preds = models.get_individual_predictions(features)

        # Convert predictions to labels
        individual_results = {}
        for model, pred in individual_preds.items():
            individual_results[model] = "spam" if pred[0] == 1 else "ham"

        return {
            "prediction": result,
            "individual_predictions": individual_results,
            "processed_text": processed_text
        }

    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}

@app.route('/')
def dashboard():
    """Dashboard homepage route."""
    avg_accuracy = 0.0
    if all_metrics:
        selected_metrics = all_metrics.get('lr')
        if selected_metrics is None and len(all_metrics) > 0:
            selected_metrics = next(iter(all_metrics.values()))

        if isinstance(selected_metrics, dict):
            avg_accuracy = float(selected_metrics.get('accuracy', 0.0))

    return render_template('dashboard.html',
                         stats=dashboard_stats,
                         avg_accuracy=f"{avg_accuracy:.1%}")

@app.route('/detection')
def detection():
    """Spam detection page route."""
    return render_template('detection.html')

@app.route('/performance')
def performance():
    """Model performance page route."""
    if all_metrics is None:
        return render_template('performance.html', error="Metrics not available. Please train the models first.")

    # Prepare data for template
    metrics_data = {}
    for model_name, metrics in all_metrics.items():
        metrics_data[model_name] = {
            'accuracy': f"{metrics['accuracy']:.4f}",
            'precision': f"{metrics['precision']:.4f}",
            'recall': f"{metrics['recall']:.4f}",
            'f1_score': f"{metrics['f1_score']:.4f}"
        }

    # Model characteristics
    characteristics = evaluator.get_model_characteristics()

    return render_template('performance.html',
                         metrics=metrics_data,
                         characteristics=characteristics)

@app.route('/statistics')
def statistics():
    """Dataset statistics page route."""
    try:
        # Load dataset
        df = pd.read_csv(DATASET_PATH)

        # Calculate statistics
        total_emails = len(df)
        spam_count = len(df[df['label'] == 'spam'])
        ham_count = len(df[df['label'] == 'ham'])
        spam_percentage = (spam_count / total_emails) * 100
        ham_percentage = (ham_count / total_emails) * 100

        stats = {
            'total_emails': total_emails,
            'spam_count': spam_count,
            'ham_count': ham_count,
            'spam_percentage': f"{spam_percentage:.1f}",
            'ham_percentage': f"{ham_percentage:.1f}"
        }

        return render_template('statistics.html', stats=stats)
    except Exception as e:
        return render_template('statistics.html', error=f"Error loading dataset: {str(e)}")

@app.route('/about')
def about():
    """About page route."""
    return render_template('about.html')

# Keep old routes for backward compatibility
@app.route('/metrics')
def metrics():
    """Model performance metrics route (redirect to performance)."""
    return performance()

if __name__ == '__main__':
    # Try to load existing models on startup
    loaded = load_model()
    if not loaded and os.path.exists(DATASET_PATH):
        print('Model load failed. Attempting to train models from dataset...')
        if not train_model():
            print('Model training failed. Predictions may be unavailable until models are fixed.')

    # Run Flask app
    app.run(debug=True, host='127.0.0.1', port=5000)