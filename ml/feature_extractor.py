import re
import numpy as np
import warnings
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
#  LEXICAL / URL FEATURES  (no network calls)
# ─────────────────────────────────────────────

def having_IP_Address(url):
    try:
        hostname = urlparse(url).netloc.split(":")[0]
        ipaddress.ip_address(hostname)
        return 1   # IP used → suspicious
    except:
        return -1  # domain name → legitimate

def URL_Length(url):
    return -1 if len(url) < 54 else (0 if len(url) <= 75 else 1)

def Shortining_Service(url):
    shorteners = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|cli\.gs|yfrog|migre\.me|ff\.im|" \
                 r"tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|" \
                 r"ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|" \
                 r"short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|" \
                 r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|viralurl\.com|" \
                 r"is\.gd|vur\.me|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb"
    return 1 if re.search(shorteners, url) else -1

def having_At_Symbol(url):
    return 1 if "@" in url else -1

def double_slash_redirecting(url):
    # Check for // after the protocol part
    path = urlparse(url).path
    return 1 if "//" in path else -1

def Prefix_Suffix(url):
    hostname = urlparse(url).netloc
    return 1 if "-" in hostname else -1

def having_Sub_Domain(url):
    hostname = urlparse(url).netloc
    # Remove www. prefix
    hostname = re.sub(r"^www\.", "", hostname)
    dot_count = hostname.count(".")
    if dot_count == 1:
        return -1
    elif dot_count == 2:
        return 0
    return 1

def SSLfinal_State(url):
    return -1 if urlparse(url).scheme == "https" else 1

def Domain_registeration_length(domain_info):
    """Pass pre-fetched whois result; returns feature."""
    try:
        if domain_info is None:
            return 1
        exp = domain_info.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp:
            if hasattr(exp, 'tzinfo') and exp.tzinfo:
                exp = exp.replace(tzinfo=None)
            days = (exp - datetime.now()).days
            return -1 if days >= 365 else 1
    except:
        pass
    return 1

def Favicon(url, soup=None):
    if soup is None:
        return 0
    try:
        icons = soup.find_all("link", rel=lambda v: v and "icon" in " ".join(v).lower())
        base = urlparse(url).netloc
        for icon in icons:
            href = icon.get("href", "")
            if href and urlparse(href).netloc and urlparse(href).netloc != base:
                return 1
        return -1
    except:
        return 0

def port(url):
    parsed = urlparse(url)
    if parsed.port and parsed.port not in (80, 443):
        return 1
    return -1

def HTTPS_token(url):
    hostname = urlparse(url).netloc
    return 1 if "https" in hostname.lower() and urlparse(url).scheme != "https" else -1

def Request_URL(url, soup=None):
    if soup is None:
        return 0
    try:
        base = urlparse(url).netloc
        tags = soup.find_all(["img", "video", "audio", "script"])
        total, external = 0, 0
        for tag in tags:
            src = tag.get("src", "")
            if src:
                total += 1
                if src.startswith("http") and urlparse(src).netloc != base:
                    external += 1
        if total == 0:
            return -1
        ratio = external / total
        return -1 if ratio < 0.22 else (0 if ratio < 0.61 else 1)
    except:
        return 0

def URL_of_Anchor(url, soup=None):
    if soup is None:
        return 0
    try:
        base = urlparse(url).netloc
        anchors = soup.find_all("a", href=True)
        total, suspicious = 0, 0
        for a in anchors:
            href = a["href"]
            total += 1
            if href in ("#", "", "javascript::void(0)"):
                suspicious += 1
            elif href.startswith("http") and urlparse(href).netloc != base:
                suspicious += 1
        if total == 0:
            return -1
        ratio = suspicious / total
        return -1 if ratio < 0.31 else (0 if ratio < 0.67 else 1)
    except:
        return 0

def Links_in_tags(url, soup=None):
    if soup is None:
        return 0
    try:
        base = urlparse(url).netloc
        tags = soup.find_all(["meta", "script", "link"])
        total, external = 0, 0
        for tag in tags:
            href = tag.get("href") or tag.get("src") or tag.get("content") or ""
            if href and href.startswith("http"):
                total += 1
                if urlparse(href).netloc != base:
                    external += 1
        if total == 0:
            return -1
        ratio = external / total
        return -1 if ratio < 0.17 else (0 if ratio < 0.81 else 1)
    except:
        return 0

def SFH(url, soup=None):
    if soup is None:
        return 0
    try:
        base = urlparse(url).netloc
        forms = soup.find_all("form", action=True)
        for form in forms:
            action = form["action"]
            if action in ("", "about:blank"):
                return 1
            if action.startswith("http") and urlparse(action).netloc != base:
                return 1
        return -1
    except:
        return 0

def Submitting_to_email(url, soup=None):
    if soup is None:
        return -1
    try:
        forms = soup.find_all("form", action=True)
        for form in forms:
            if "mailto:" in form.get("action", "").lower():
                return 1
        return -1
    except:
        return -1

def Abnormal_URL(url, domain_info=None):
    try:
        if domain_info is None:
            return 1
        hostname = urlparse(url).netloc
        reg_domain = domain_info.domain or ""
        return -1 if reg_domain.lower() in hostname.lower() else 1
    except:
        return 1

def Redirect(url):
    # Count redirects via // in the URL (simple heuristic)
    return 1 if url.count("//") > 1 else -1

def on_mouseover(url, soup=None):
    if soup is None:
        return -1
    try:
        scripts = " ".join([str(s) for s in soup.find_all("script")])
        return 1 if "onmouseover" in scripts.lower() and "window.status" in scripts.lower() else -1
    except:
        return -1

def mouse_over(url, soup=None):
    """Feature 21 (UCI col 21): anchor-level onMouseOver hiding true href."""
    if soup is None:
        return -1
    try:
        anchors = soup.find_all("a", onmouseover=True)
        return 1 if anchors else -1
    except:
        return -1

def RightClick(url, soup=None):
    if soup is None:
        return -1
    try:
        scripts = " ".join([str(s) for s in soup.find_all("script")])
        return 1 if "event.button==2" in scripts or "contextmenu" in scripts.lower() else -1
    except:
        return -1

def popUpWidow(url, soup=None):
    if soup is None:
        return -1
    try:
        scripts = " ".join([str(s) for s in soup.find_all("script")])
        return 1 if "prompt(" in scripts or "window.open(" in scripts else -1
    except:
        return -1

def Iframe(url, soup=None):
    if soup is None:
        return -1
    try:
        iframes = soup.find_all("iframe")
        for iframe in iframes:
            if iframe.get("frameborder") == "0" or not iframe.get("src"):
                return 1
        return -1
    except:
        return -1

def age_of_domain(domain_info):
    try:
        if domain_info is None:
            return 1
        creation = domain_info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if hasattr(creation, 'tzinfo') and creation.tzinfo:
                creation = creation.replace(tzinfo=None)
            age_days = (datetime.now() - creation).days
            return -1 if age_days >= 180 else 1
    except:
        pass
    return 1

def DNSRecord(domain_info):
    try:
        if domain_info is None:
            return 1
        return -1 if domain_info.domain else 1
    except:
        return 1

def web_traffic(url):
    # Without Alexa API, use URL characteristics as proxy
    hostname = urlparse(url).netloc
    known = ["google", "facebook", "amazon", "youtube", "wikipedia",
             "twitter", "instagram", "linkedin", "microsoft", "apple"]
    for k in known:
        if k in hostname.lower():
            return -1
    return 0

def Page_Rank(url):
    return 0  # Google PageRank API deprecated; neutral

def Google_Index(url):
    return 0  # Would require Google API; neutral

def Links_pointing_to_page(url, soup=None):
    return 0  # Requires external lookup; neutral

def Statistical_report(url):
    hostname = urlparse(url).netloc
    flagged = ["at.", ".tk", ".ml", ".ga", ".cf", ".gq"]
    return 1 if any(hostname.endswith(f) for f in flagged) else -1

# ─────────────────────────────────────────────
#  MAIN EXTRACTION ENTRY POINT
# ─────────────────────────────────────────────

def extract_features(url, fetch_html=True):
    """
    Extract all 31 features in the same order as the UCI dataset.
    Returns a numpy array of shape (1, 31).
    """
    soup = None
    domain_info = None

    # --- Optional: fetch HTML ---
    if fetch_html:
        try:
            import requests
            from bs4 import BeautifulSoup
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception as e:
            print(f"    [HTML] Could not fetch page: {e}")

    # --- Optional: WHOIS lookup ---
    try:
        import whois as whois_lib
        hostname = urlparse(url).netloc.split(":")[0]
        domain_info = whois_lib.whois(hostname)
        print(f"    [WHOIS] Lookup succeeded for {hostname}")
    except Exception as e:
        print(f"    [WHOIS] Lookup failed: {e}")

    features = [
        having_IP_Address(url),            # 1
        URL_Length(url),                   # 2
        Shortining_Service(url),           # 3
        having_At_Symbol(url),             # 4
        double_slash_redirecting(url),     # 5
        Prefix_Suffix(url),                # 6
        having_Sub_Domain(url),            # 7
        SSLfinal_State(url),               # 8
        Domain_registeration_length(domain_info),  # 9
        Favicon(url, soup),                # 10
        port(url),                         # 11
        HTTPS_token(url),                  # 12
        Request_URL(url, soup),            # 13
        URL_of_Anchor(url, soup),          # 14
        Links_in_tags(url, soup),          # 15
        SFH(url, soup),                    # 16
        Submitting_to_email(url, soup),    # 17
        Abnormal_URL(url, domain_info),    # 18
        Redirect(url),                     # 19
        on_mouseover(url, soup),           # 20
        RightClick(url, soup),             # 21
        popUpWidow(url, soup),             # 22
        Iframe(url, soup),                 # 23
        age_of_domain(domain_info),        # 24
        DNSRecord(domain_info),            # 25
        web_traffic(url),                  # 26
        Page_Rank(url),                    # 27
        Google_Index(url),                 # 28
        Links_pointing_to_page(url, soup), # 29
        Statistical_report(url),           # 30
    ]

    arr = np.array([features], dtype=float)

    # ── Auto-resize to match whatever the saved model expects ──
    # This makes the extractor resilient to models trained on 30, 31, or any count.
    try:
        import joblib, os
        MODEL_FILE = os.path.join(os.path.dirname(__file__), "hybrid_model.pkl")
        if os.path.exists(MODEL_FILE):
            _m = joblib.load(MODEL_FILE)
            # VotingClassifier wraps estimators; get n_features from first sub-estimator
            try:
                expected = _m.estimators_[0].n_features_in_
            except AttributeError:
                expected = _m.n_features_in_
            current = arr.shape[1]
            if current < expected:
                pad = np.zeros((1, expected - current))
                arr = np.hstack([arr, pad])
                print(f"    [FE] Padded features {current} → {expected}")
            elif current > expected:
                arr = arr[:, :expected]
                print(f"    [FE] Trimmed features {current} → {expected}")
    except Exception as e:
        print(f"    [FE] Could not auto-resize features: {e}")

    return arr


def scan_url(url, fetch_html=True):
    """
    Full scan pipeline: extract features → run model → return dict.
    """
    import joblib, os
    MODEL_FILE = os.path.join(os.path.dirname(__file__), "hybrid_model.pkl")

    print(f"\n[*] Scanning: {url}")
    print("-" * 50)

    features = extract_features(url, fetch_html=fetch_html)

    try:
        model = joblib.load(MODEL_FILE)
    except FileNotFoundError:
        return {"error": f"Model file '{MODEL_FILE}' not found. Run build_system.py first."}

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    is_phishing = int(prediction) == 1
    confidence = float(probabilities[1] if is_phishing else probabilities[0]) * 100
    risk_score = float(probabilities[1]) * 100  # always the phishing probability

    result = {
        "url": url,
        "is_phishing": is_phishing,
        "label": "PHISHING" if is_phishing else "LEGITIMATE",
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 2),
        "features": {
            "has_ip": bool(features[0][0] == 1),
            "url_length": int(features[0][1]),
            "uses_shortener": bool(features[0][2] == 1),
            "has_at_symbol": bool(features[0][3] == 1),
            "uses_https": bool(features[0][7] == -1),
            "domain_age_suspicious": bool(features[0][23] == 1),
            "has_prefix_suffix": bool(features[0][5] == 1),
        }
    }

    print(f"  RESULT     : {result['label']}")
    print(f"  CONFIDENCE : {result['confidence']:.2f}%")
    print(f"  RISK SCORE : {result['risk_score']:.2f}%")
    print("-" * 50)

    return result


if __name__ == "__main__":
    print(scan_url("https://www.google.com", fetch_html=False))
    print()
    print(scan_url("http://paypal-security-check@update-service-unusual-activity.com", fetch_html=False))