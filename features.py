import re, socket, ssl, requests
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

try:
    import whois
except Exception:
    whois = None

SHORT = r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|cutt\.ly|rebrand\.ly|tiny\.cc"

def _pct(p, lo, hi):
    return 1 if p < lo else (0 if p <= hi else -1)

def _date(d):
    if isinstance(d, list):
        d = d[0] if d else None
    if isinstance(d, datetime):
        return d.replace(tzinfo=None)
    return None

def _ssl_ok(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except Exception:
        return False

def extract_features(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host:
        raise ValueError("Invalid URL")
    domain = host[4:] if host.startswith("www.") else host
    try:
        port = p.port
    except ValueError:
        port = -1

    f = {}

    # ---------- URL based ----------
    f["having_IP_Address"] = -1 if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) else 1
    n = len(url)
    f["URL_Length"] = 1 if n < 54 else (0 if n <= 75 else -1)
    f["Shortining_Service"] = -1 if re.search(SHORT, url) else 1
    f["having_At_Symbol"] = -1 if "@" in url else 1
    f["double_slash_redirecting"] = -1 if url.rfind("//") > 7 else 1
    f["Prefix_Suffix"] = -1 if "-" in host else 1
    dots = domain.count(".")
    f["having_Sub_Domain"] = 1 if dots <= 1 else (0 if dots == 2 else -1)
    f["port"] = -1 if port not in (None, 80, 443) else 1
    f["HTTPS_token"] = -1 if "https" in host else 1

    # ---------- WHOIS / DNS ----------
    created = expires = None
    if whois is not None:
        try:
            w = whois.whois(domain)
            created = _date(w.creation_date)
            expires = _date(w.expiration_date)
        except Exception:
            pass
    now = datetime.now()
    age_days = (now - created).days if created else 0

    f["Domain_registeration_length"] = 1 if expires and (expires - now).days > 365 else -1
    f["age_of_domain"] = 1 if created and age_days >= 180 else -1
    f["Abnormal_URL"] = 1 if created else -1
    try:
        socket.gethostbyname(host)
        f["DNSRecord"] = 1
    except Exception:
        f["DNSRecord"] = -1

    # ---------- SSL (stricter) ----------
    if p.scheme == "https":
        ok = _ssl_ok(host)
        f["SSLfinal_State"] = 1 if (ok and age_days >= 365) else (0 if ok else -1)
    else:
        f["SSLfinal_State"] = -1

    # ---------- Page content based ----------
    html, hist = "", 0
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        html, hist = r.text, len(r.history)
    except Exception:
        pass
    fetched = bool(html)
    soup = BeautifulSoup(html, "html.parser")

    def ext(link):
        if not link or link.startswith(("#", "javascript", "mailto")):
            return False
        nl = urlparse(link).netloc
        return bool(nl) and domain not in nl

    imgs = [t.get("src") or t.get("data-src") for t in soup.find_all(["img", "audio", "embed", "iframe"])]
    imgs = [i for i in imgs if i]
    f["Request_URL"] = _pct(sum(map(ext, imgs)) / len(imgs) * 100, 22, 61) if imgs else 1

    anchors = [a.get("href") for a in soup.find_all("a")]
    anchors = [a for a in anchors if a is not None]
    bad = [a for a in anchors if a.startswith(("#", "javascript", "mailto")) or ext(a)]
    f["URL_of_Anchor"] = _pct(len(bad) / len(anchors) * 100, 31, 67) if anchors else 1

    tags = [t.get("href") or t.get("src") for t in soup.find_all(["meta", "script", "link"])]
    tags = [t for t in tags if t]
    f["Links_in_tags"] = _pct(sum(map(ext, tags)) / len(tags) * 100, 17, 81) if tags else 1

    sfh = 1
    for form in soup.find_all("form"):
        act = form.get("action", "") or ""
        if act in ("", "about:blank"):
            sfh = -1
            break
        if ext(act):
            sfh = 0
    f["SFH"] = sfh

    f["Submitting_to_email"] = -1 if re.search(r"mailto:|mail\(", html) else 1
    f["Redirect"] = 1 if hist <= 1 else (0 if hist < 5 else -1)
    f["on_mouseover"] = -1 if re.search(r"onmouseover\s*=\s*[\"'][^\"']*window\.status", html, re.I) else 1
    f["RightClick"] = -1 if re.search(r"event\.button\s*==\s*2|contextmenu", html, re.I) else 1
    f["popUpWidnow"] = -1 if re.search(r"window\.open\(|alert\(", html) else 1
    f["Iframe"] = -1 if soup.find("iframe") else 1

    icon = soup.find("link", rel=lambda v: v and "icon" in str(v).lower())
    f["Favicon"] = -1 if icon and ext(icon.get("href")) else 1

    # Page open aagala na suspicious
    if not fetched:
        for k in ["Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH"]:
            f[k] = -1

    # extra info (model-ku pogaadhu, app-la use aagum)
    f["_fetched"] = fetched
    f["_age_days"] = age_days
    return f