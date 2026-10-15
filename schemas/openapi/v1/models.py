"""Reference models for the shared /api/v1 fixtures.

Each function states one rule of docs/specs/api-foundation.md, identity-login.md,
identity-sessions.md or change-stream.md in executable form. validate.py compares every
fixture expectation with these models, so the Go server and the console tests that consume
the same fixtures cannot drift from the specification without a fixture change.
"""
import base64
import hashlib
import hmac
import json
import re

ORIGIN = 'https://console.example.test'

# Problem types in Problem.type enum order, with their HTTP status (api-foundation section 4).
PROBLEMS = {
    'validation_failed': 400, 'unauthenticated': 401, 'reauth_required': 401,
    'invalid_credentials': 401, 'permission_denied': 403, 'csrf_rejected': 403,
    'credentials_ambiguous': 400, 'not_found': 404, 'method_not_allowed': 405,
    'conflict': 409, 'approval_stale': 409, 'idempotency_in_progress': 409,
    'precondition_failed': 412, 'payload_too_large': 413, 'unsupported_media_type': 415,
    'idempotency_key_reused': 422, 'precondition_required': 428, 'rate_limited': 429,
    'internal_error': 500, 'unavailable': 503, 'recovery_sealed': 503,
}
ONLY_WITH = {'errors': {'validation_failed'}, 'permission': {'permission_denied'},
             'reauth': {'reauth_required'}, 'retry_after_seconds': {'rate_limited', 'unavailable', 'recovery_sealed'}}

LOGIN_ERRORS = {'provider_error', 'state_mismatch', 'expired', 'invalid_response', 'no_link',
                'link_pending', 'user_disabled', 'provider_disabled', 'cross_site_start',
                'rate_limited', 'unavailable', 'reauth_user_mismatch', 'reauth_stale',
                'session_required'}

RESERVED_PREFIXES = ('/api', '/agent', '/ext', '/assets', '/brand', '/mdm', '/scep', '/acme',
                     '/healthz', '/readyz', '/metrics', '/login', '/__test__')

TOPIC_PERMISSIONS = {
    'devices': 'mdm.devices.read', 'alerts': 'edr.alerts.read', 'dlp.findings': 'dlp.findings.read',
    'approvals': None, 'enrollments': 'mdm.enrollments.read',
    'certificates': 'pki.certificates.read', 'certificates.infrastructure': 'pki.infrastructure.read',
    'rollouts': 'mdm.rollouts.read', 'extensions': 'extensions.packages.read',
    'exports': 'events.destinations.read', 'device': 'mdm.devices.read', 'alert': 'edr.alerts.read',
    'commands': 'mdm.commands.read',
}
UID = r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
TOPIC = re.compile(r'^(devices|alerts|dlp\.findings|approvals|enrollments|certificates|'
                   r'certificates\.infrastructure|rollouts|extensions|exports|(device|alert|commands)/' + UID + r')$')

TIMEOUT_RANGES = {'sso': ((300, 3600), (3600, 43200)), 'break_glass': ((120, 900), (900, 14400))}
ACTIVITY_GRANULARITY = 30

COOKIES = {
    'session': '__Host-rv_session={v}; Path=/; HttpOnly; Secure; SameSite=Strict',
    'session_clear': '__Host-rv_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict',
    'login': '__Host-rv_login={v}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax',
    'login_clear': '__Host-rv_login=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
    'saml': '__Host-rv_saml={v}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None',
    'saml_clear': '__Host-rv_saml=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None',
    'enroll': '__Host-rv_enroll={v}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Strict',
    'enroll_clear': '__Host-rv_enroll=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict',
}
COOKIE_VALUE = re.compile(r'^[A-Za-z0-9_-]{43}$')


def problem_semantics(problem):
    code = problem['type'].rsplit('/', 1)[1]
    if problem['title'] != code.replace('_', ' ').capitalize():
        return False
    if PROBLEMS.get(code) != problem['status']:
        return False
    if 'instance' in problem and problem['instance'] != 'urn:uuid:' + problem['request_id']:
        return False
    return all(field not in problem or code in codes for field, codes in ONLY_WITH.items())


def media_essence(value):
    if value is None:
        return None
    parts = [p.strip().lower() for p in value.split(';')]
    if len(parts) > 2 or any(p != 'charset=utf-8' for p in parts[1:]):
        return None
    return parts[0]


def guard(c):
    """Credential, resource-isolation and request-forgery checks (identity-sessions section 4)."""
    unsafe = c['method'] in ('POST', 'PUT', 'PATCH', 'DELETE')
    credentials = c['credentials']
    if not credentials and c['bearer'] != 'absent':
        return 'unauthenticated'
    if credentials and c['session_cookie'] != 'absent' and c['bearer'] != 'absent':
        return 'credentials_ambiguous'
    site = c['sec_fetch_site']
    if site in ('cross-site', 'same-site'):
        if c['csrf'] == 'navigation':
            return 'redirect:cross_site_start'
        if c['csrf'] not in ('navigation_callback', 'cross_site_post'):
            return 'csrf_rejected'
    if unsafe and site == 'none' and c['csrf'] in ('synchronizer', 'origin'):
        return 'csrf_rejected'
    token = False
    if credentials:
        if c['bearer'] != 'absent':
            if 'token' not in credentials or c['bearer'] == 'invalid':
                return 'unauthenticated'
            token = True
        elif c['session_cookie'] != 'valid':
            return 'redirect:session_required' if c['csrf'] == 'navigation' else 'unauthenticated'
    if c['csrf'] in ('synchronizer', 'origin') and not token and c['origin'] != ORIGIN:
        return 'csrf_rejected'
    if c['body']:
        expected = 'application/x-www-form-urlencoded' if c['csrf'] == 'cross_site_post' else 'application/json'
        if media_essence(c['content_type']) != expected:
            return 'unsupported_media_type'
    if c['csrf'] == 'synchronizer' and not token and c['csrf_header'] != 'match':
        return 'csrf_rejected'
    return 'allow'


def return_path(value):
    """Effective post-login path (identity-login section 2.2): invalid input becomes '/'."""
    if not isinstance(value, str) or len(value.encode()) > 512:
        return '/'
    if not re.fullmatch(r'/[A-Za-z0-9._~/-]*', value):
        return '/'
    if value != '/' and any(s in ('', '.', '..') for s in value[1:].split('/')):
        return '/'
    if any(value == p or value.startswith(p + '/') for p in RESERVED_PREFIXES):
        return '/'
    return value


def hotp(secret, counter, digits):
    mac = hmac.new(secret, counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = int.from_bytes(mac[offset:offset + 4], 'big') & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp_verify(secret, now, code, last_step):
    """RFC 6238 with 30 s steps; accept the current and the previous step once (identity-login 6.2)."""
    step = now // 30
    for candidate in (step, step - 1):
        if candidate >= 0 and hmac.compare_digest(hotp(secret, candidate, 6), code):
            if last_step is not None and candidate <= last_step:
                return {'accepted': False, 'reason': 'replay'}
            return {'accepted': True, 'step': candidate}
    return {'accepted': False, 'reason': 'mismatch'}


def session_state(c):
    if c['revoked']:
        return 'revoked'
    if c['now'] >= c['created_at'] + c['absolute_timeout']:
        return 'absolute_expired'
    if c['now'] >= c['last_activity_at'] + c['idle_timeout']:
        return 'idle_expired'
    return 'valid'


def activity(c):
    if not c.get('authorized', True) or c.get('expired', False) or c['background'] or c['now'] - c['stored_last_activity'] < ACTIVITY_GRANULARITY:
        return c['stored_last_activity']
    return c['now']


def timeout_config(c):
    (idle_lo, idle_hi), (abs_lo, abs_hi) = TIMEOUT_RANGES[c['session_kind']]
    return idle_lo <= c['idle'] <= idle_hi and abs_lo <= c['absolute'] <= abs_hi and c['idle'] < c['absolute']


def login(f):
    """Callback and assertion-consumer decision order (identity-login sections 3 and 4)."""
    cookie = f['login_cookie'] if f['protocol'] == 'oidc' else f['saml_cookie']
    if not cookie or f['record'] in ('missing', 'consumed') or not f['record_provider_match']:
        return 'state_mismatch'
    if f['record'] == 'expired':
        return 'expired'
    if f['protocol'] == 'oidc':
        if not f['state_match']:
            return 'state_mismatch'
    elif f['in_response_to'] != 'match':
        return 'state_mismatch'
    if not f['provider_enabled']:
        return 'provider_disabled'
    if f['protocol'] == 'oidc':
        if f['error_param']:
            return 'provider_error'
        if f['iss_param'] == 'mismatch' or (f['iss_supported'] and f['iss_param'] == 'absent'):
            return 'invalid_response'
        if not f['code_present']:
            return 'invalid_response'
        if f['token_exchange'] == 'rejected':
            return 'provider_error'
        if f['token_exchange'] == 'unreachable':
            return 'unavailable'
        if not all(f['id_token'].values()):
            return 'invalid_response'
        fresh = f['auth_time'] == 'fresh'
    else:
        if f['destination'] != 'match':
            return 'invalid_response'
        if not f['status_success']:
            return 'provider_error'
        if not f['issuer_match'] or f['assertion_count'] != 1 or not f['assertion_signature_valid']:
            return 'invalid_response'
        checks = ('bearer_confirmation', 'recipient_match', 'confirmation_unexpired', 'confirmation_window_ok',
                  'conditions_time_ok', 'audience_match', 'authn_statement', 'name_id_persistent')
        if not all(f[name] for name in checks) or f['replayed']:
            return 'invalid_response'
        fresh = f['authn_instant'] == 'fresh'
    reauth = f['purpose'] == 'reauth'
    if reauth and not fresh:
        return 'reauth_stale'
    if reauth and not f['session_valid']:
        return 'session_required'
    if f['link'] == 'unlinked':
        return 'link_pending'
    if f['link'] == 'request_cap':
        return 'rate_limited'
    if not f['user_enabled']:
        return 'user_disabled'
    if reauth and not f['same_user']:
        return 'reauth_user_mismatch'
    return 'reauthenticated' if reauth else 'session_created'


def sse_encode(items):
    out = []
    for item in items:
        if item['kind'] == 'retry':
            out.append(f'retry: {item["ms"]}\n\n')
        elif item['kind'] == 'comment':
            out.append(f': {item["text"]}\n\n')
        else:
            data = json.dumps(item['data'], separators=(',', ':'), sort_keys=True, ensure_ascii=True)
            out.append(f'event: {item["event"]}\ndata: {data}\n\n')
    return ''.join(out)


def sse_parse(chunks):
    """WHATWG HTML event-stream interpretation over the concatenated chunks."""
    text = ''.join(chunks)
    if text.startswith('﻿'):
        text = text[1:]
    lines = re.split(r'\r\n|\r|\n', text)
    complete = lines[:-1]
    events, data, event_type, last_id, retry = [], '', '', '', None
    for line in complete:
        if line == '':
            if data:
                events.append({'event': event_type or 'message', 'data': data[:-1], 'last_event_id': last_id})
            data, event_type = '', ''
            continue
        if line.startswith(':'):
            continue
        field, _, value = line.partition(':')
        if value.startswith(' '):
            value = value[1:]
        if field == 'event':
            event_type = value
        elif field == 'data':
            data += value + '\n'
        elif field == 'id' and '\x00' not in value:
            last_id = value
        elif field == 'retry' and value.isascii() and value.isdigit():
            retry = int(value)
    return {'events': events, 'retry': retry}


def subscribe(c):
    topics = c['topics']
    if not 1 <= len(topics) <= 16 or len(set(topics)) != len(topics):
        return {'problem': 'validation_failed'}
    if not all(TOPIC.fullmatch(t) for t in topics):
        return {'problem': 'validation_failed'}
    for topic in topics:
        permission = TOPIC_PERMISSIONS[topic.split('/')[0]]
        if permission is not None and permission not in c['permissions']:
            return {'problem': 'permission_denied'}
    for topic in topics:
        if '/' in topic and not c['visible'].get(topic.split('/')[1], False):
            return {'problem': 'not_found'}
    return {'accepted': topics}


def _b32(value):
    return base64.b32decode(value + '=' * (-len(value) % 8))


def check(name, data, bundle, instance_validator, operations):
    """Compare one fixture file with the reference models; return diagnostics."""
    out = []
    for case in data['cases']:
        where = f'F10 fixtures/{name}.json {case["id"]}'
        if name == 'problems':
            valid = instance_validator(bundle, 'Problem').is_valid(case['problem'])
            valid = valid and problem_semantics(case['problem'])
            if valid != case['valid']:
                out.append(f'{where}: expected valid={case["valid"]}')
        elif name == 'http-guards':
            if guard(case['request']) != case['expect']:
                out.append(f'{where}: model gives {guard(case["request"])}')
        elif name == 'return-paths':
            if return_path(case['input']) != case['expect']:
                out.append(f'{where}: model gives {return_path(case["input"])}')
        elif name == 'totp':
            seed = case['rfc_seed_ascii'].encode('ascii')
            secret = _b32(base64.b32encode(seed).decode('ascii').rstrip('='))
            if secret != seed:
                out.append(f'{where}: base32 round trip mismatch')
            if case['kind'] == 'rfc':
                if hotp(secret, case['time'] // 30, 8) != case['rfc_code_8'] or \
                        hotp(secret, case['time'] // 30, 6) != case['code_6']:
                    out.append(f'{where}: RFC 6238 vector mismatch')
            else:
                got = totp_verify(secret, case['now'], case['code'], case['last_step'])
                if got != case['expect']:
                    out.append(f'{where}: model gives {got}')
        elif name == 'sse':
            if case['kind'] == 'encode':
                if sse_encode(case['items']) != case['expect']:
                    out.append(f'{where}: encoder mismatch')
                for item in case['items']:
                    if item['kind'] == 'event':
                        schema = {'snapshot': 'ChangeSnapshot', 'change': 'ChangeEvent',
                                  'session': 'SessionEvent', 'reconnect': 'ReconnectEvent'}[item['event']]
                        if not instance_validator(bundle, schema).is_valid(item['data']):
                            out.append(f'{where}: event data fails {schema}')
            elif case['kind'] == 'parse':
                if sse_parse(case['chunks']) != case['expect']:
                    out.append(f'{where}: parser gives {sse_parse(case["chunks"])}')
            elif subscribe(case['request']) != case['expect']:
                out.append(f'{where}: model gives {subscribe(case["request"])}')
        elif name == 'sessions':
            kind = case['kind']
            if kind == 'timeout':
                got = session_state(case['input'])
            elif kind == 'activity':
                got = activity(case['input'])
            elif kind == 'config':
                got = timeout_config(case['input'])
            else:
                value = case['input'].get('value', '')
                if value and not COOKIE_VALUE.match(value):
                    out.append(f'{where}: cookie value must be 43 base64url characters')
                got = COOKIES[case['input']['cookie']].format(v=value)
            if got != case['expect']:
                out.append(f'{where}: model gives {got!r}')
        elif name == 'login':
            got = login(case['facts'])
            if got != case['expect']:
                out.append(f'{where}: model gives {got}')
            if got not in LOGIN_ERRORS | {'session_created', 'reauthenticated'}:
                out.append(f'{where}: unknown outcome {got}')
        elif name == 'security':
            got = security(case['kind'], case['input'])
            if got != case['expect']:
                out.append(f'{where}: security model mismatch')
        elif name == 'wire':
            valid = instance_validator(bundle, case['schema']).is_valid(case['value'])
            if valid != case['valid']:
                out.append(f'{where}: wire schema acceptance mismatch')
        elif name == 'document-mutations':
            if not case['expect'].startswith(('R', 'Y', 'S', 'C')):
                out.append(f'{where}: expectation must name a rule code')
    return out


def fresh(c):
    """Verified evidence, not session issuance, supplies freshness (sessions section 5)."""
    at = c.get('authenticated_at')
    if not c['verified'] or at is None or not 0 <= c['now'] - at < 600:
        return False
    if c['binding'] == 'general':
        return True
    return (c['evidence_purpose'] == c['binding'] and c['hash_match']
            and c['epoch_match'] and not c['consumed'] and c['unaffected'])


def security(kind, c):
    if kind == 'fresh':
        return fresh(c)
    if kind == 'authority':
        # This is an acceptance predicate, not an implementation of the BE-12 fence.
        return all(c[k] for k in ('mac_valid', 'epoch_current', 'generation_current',
                                  'dependencies_current', 'lease_live', 'published')) and not c['denied']
    if kind == 'decision':
        return (c['route_kind'] == c['request_kind'] and c['pending'] and c['hash_match']
                and c['eligible'] and c['different_user'] and not c['target_user']
                and c['fresh'] and (c['request_kind'] != 'identity_authority'
                    or c['decision'] == 'reject' or (c['bound'] and c['unaffected'])))
    if kind == 'enrollment':
        return (c['epoch_current'] and c['generation_current'] and not c['consumed']
                and c['now'] < c['expires_at'] and c['attempts'] < 5 and c['proof_valid'])
    raise ValueError('unknown security fixture kind')
