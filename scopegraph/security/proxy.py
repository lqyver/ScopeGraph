from urllib.parse import urlsplit, urlunsplit


def normalize_proxy_url(value: str) -> str:
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        raise ValueError("Proxy URL is empty or too long")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Proxy URL has an invalid host or port") from exc
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Proxy URL must use HTTP or HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Proxy credentials must not be embedded in the URL")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Proxy URL must not include a path, query, or fragment")
    host = parsed.hostname.casefold()
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.casefold(), netloc, "", "", ""))
