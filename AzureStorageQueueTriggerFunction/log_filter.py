import re


def sanitize_logs(logs: str) -> str:
    patterns = [
        (r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', '[TIMESTAMP]'),
        (r'0x[0-9a-fA-F]+', '[MEM_ADDR]'),
        # Emails
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]'),
        # API keys
        (r'(?i)(api[_-]?key["=: ]+)([^\s,"\']+)', r'\1[REDACTED]'),
        # Passwords
        (r'(?i)(password["=: ]+)([^\s,"\']+)', r'\1[REDACTED]'),
        # Authorization headers
        (r'(?i)(authorization["=: ]+)([^\n]+)', r'\1[REDACTED]')
    ]
    patterns.extend([
    (r'AKIA[0-9A-Z]{16}',
     '[AWS_ACCESS_KEY]'),

    (r'AIza[0-9A-Za-z\-_]{35}',
     '[GOOGLE_API_KEY]'),

    (r'ghp_[A-Za-z0-9]{36}',
     '[GITHUB_TOKEN]'),

    (r'github_pat_[A-Za-z0-9_]+',
     '[GITHUB_FINE_GRAINED_TOKEN]')
    ])
    patterns.extend([
    (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]'),
    (r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[JWT_REDACTED]'),
    (r'(?i)(authorization\s*:\s*)(.*)', r'\1[REDACTED]'),
    (r'(?i)(api[_-]?key\s*[:=]\s*)(\S+)', r'\1[REDACTED]'),
    (r'(?i)(secret\s*[:=]\s*)(\S+)', r'\1[REDACTED]'),
    (r'(?i)(client[_-]?secret\s*[:=]\s*)(\S+)', r'\1[REDACTED]'),
    (r'(?i)(password\s*[:=]\s*)(\S+)', r'\1[REDACTED]'),
    (r'(?i)(passwd\s*[:=]\s*)(\S+)', r'\1[REDACTED]'),
    (r'(?i)(token\s*[:=]\s*)(\S+)', r'\1[REDACTED]')
    ])
    patterns.extend([
    (r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
     '[TIMESTAMP]'),

    (r'0x[0-9a-fA-F]+',
     '[MEM_ADDR]'),

    (r'\b[0-9a-f]{32}\b',
     '[MD5_HASH]'),

    (r'\b[0-9a-f]{40}\b',
     '[SHA1_HASH]'),

    (r'\b[0-9a-f]{64}\b',
     '[SHA256_HASH]')
    ])
    scrubbed_logs = logs
    for pattern, replacement in patterns:
        scrubbed_logs = re.sub(pattern, replacement, scrubbed_logs)
    return scrubbed_logs
