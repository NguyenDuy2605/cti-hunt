"""Read new reports without labels. Preserve source bytes and auditable locations.

Images are inventoried, never silently treated as OCR text. PDF layout remains
heuristic: review.html explicitly requests review, even when text was extracted.
"""
from __future__ import annotations

import hashlib
import html
import http.client
import io
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from statistics import median
from urllib.parse import urljoin, urlsplit

VERSION = "report_ingest_v1"
MAX_BYTES = 25 * 1024 * 1024
MAX_PAGES = 200


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def public_address(url: str) -> tuple[str, int, str]:
    """Resolve once; the HTTP connection is pinned to the validated address."""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("URL phải là HTTP(S) công khai, không chứa thông tin đăng nhập")
    port = u.port or (443 if u.scheme == "https" else 80)
    if port not in (80, 443):
        raise ValueError("Chỉ hỗ trợ cổng HTTP 80 / HTTPS 443")
    addresses = sorted({a[4][0] for a in socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("Từ chối URL nội bộ hoặc địa chỉ không công khai")
    return u.hostname, port, addresses[0]


def fetch(url: str) -> tuple[bytes, str, str]:
    for _ in range(6):
        host, port, address = public_address(url)
        u = urlsplit(url)
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        con = cls(host, port, timeout=30)
        # Keep the hostname for TLS SNI/certificate verification, pin only the TCP peer.
        con._create_connection = lambda *a, **kw: socket.create_connection((address, port), timeout=30)
        try:
            con.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""),
                        headers={"User-Agent": "cti-hunt-report-ingest/1", "Accept-Encoding": "identity"})
            response = con.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    raise ValueError("Redirect không có Location")
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise ValueError(f"Không tải được report: HTTP {response.status}; có thể dùng HTML lưu cục bộ")
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError("Máy chủ gửi nội dung nén ngoài phạm vi hỗ trợ")
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Report vượt giới hạn 25 MiB")
            return raw, response.getheader("Content-Type", ""), url
        finally:
            con.close()
    raise ValueError("Report chuyển hướng quá 5 lần")


def _dom_path(node) -> str:
    parts = []
    while getattr(node, "name", None) and node.name != "[document]":
        siblings = node.find_previous_siblings(node.name)
        parts.append(f"{node.name}:nth-of-type({len(siblings) + 1})")
        node = node.parent
    return " > ".join(reversed(parts))


_RELATED_HEADING = re.compile(r"related\b.*|you (?:may|might) also (?:like|enjoy)|recommended(?: for you| reading)?"
                              r"|more from\b.*|read next|upcoming events", re.I)


# Cảnh báo về việc chọn vùng nội dung: đọc nhầm vùng tệ hơn ảnh chưa đọc, nên đưa trạng thái về needs_review.
SELECTION_ALERTS = ("html_root_fallback", "html_content_suspect")
_PROSE_TAGS = ["p", "pre", "tr", "li"]
_ROOT_SHARE = 0.5        # khối article/main phải chứa ít nhất chừng này chữ đoạn văn của trang
_DESCEND_SHARE = 0.8     # khi chọn lại: đi xuống khối con còn giữ chừng này chữ đoạn văn
_MIN_PAGE_PROSE = 1000   # trang quá ít chữ thì không so tỷ lệ
_LONG_BLOCK = 80         # khối chữ "dài" (ký tự)
_MIN_LONG_BLOCKS = 3
_MENU_ITEM = 25          # mục ngắn kiểu menu (ký tự)
_MIN_MENU_ITEMS = 5


def _prose(t) -> int:
    """Lượng chữ trong đoạn văn, khối mã, dòng bảng và mục danh sách — thước đo nội dung bài, không tính menu rời."""
    return sum(len(x.get_text(" ", strip=True)) for x in t.find_all(_PROSE_TAGS))


def _densest(page, total: int):
    """Khối nhỏ nhất còn chứa phần lớn chữ đoạn văn của trang: đi xuống khối con khi nó giữ ≥ 80% lượng chữ."""
    node = page
    while inner := [c for c in node.find_all(True, recursive=False) if _prose(c) >= _DESCEND_SHARE * total]:
        node = max(inner, key=_prose)
    return node


def _link_density(t) -> float:
    text = len(t.get_text(" ", strip=True))
    return sum(len(a.get_text(" ", strip=True)) for a in t.find_all("a")) / text if text else 0.0


def _drop_related(root) -> None:
    """Remove "Related …" card lists inside the content root (developed on two saved pages outside the
    evaluation set, 05/10). Only link lists go: a prose section titled "Related activity" has low link
    density and stays."""
    for h in root.find_all(re.compile(r"^h[1-6]$")):
        if h.decomposed or not _RELATED_HEADING.fullmatch(" ".join(h.get_text(" ", strip=True).split())):
            continue
        block = None
        for p in h.parents:
            if p is root:
                break
            if _link_density(p) >= 0.5:
                block = p
        if block is not None:
            block.decompose()


def parse_html(raw: bytes, source: str, selector: str | None = None) -> tuple[list[dict], list[dict], str]:
    try:
        from bs4 import BeautifulSoup, NavigableString, Tag
    except ImportError as e:
        raise ValueError('Cài phụ thuộc đọc report: pip install -e ".[ingest]"') from e
    soup = BeautifulSoup(raw, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    warnings = []
    if soup.contains_replacement_characters:
        warnings.append({"code": "decode_replacement", "detail": "Có ký tự không giải mã được"})
    # Capture paths before removing elements, so selectors point to the saved original.
    paths = {id(t): _dom_path(t) for t in soup.find_all(True)}
    # Remove navigation before scoring. An <article> can be only a related-post
    # card, while the real report lives in <main> or an articleBody/entry-content.
    # Dialogs (lightbox/zoom copies of figures) are overlay UI, not document flow:
    # keeping them reads every enlarged figure twice.
    for t in list(soup.select("script, style, nav, footer, aside, form, noscript, template, [hidden], [aria-hidden=true], "
                              "dialog, [role=dialog], [aria-modal=true]")):
        if t.parent is not None:
            t.decompose()
    def score(t):
        text_size = len(t.get_text(" ", strip=True))
        linked = sum(len(a.get_text(" ", strip=True)) for a in t.find_all("a"))
        paragraphs = sum(len(p.get_text(" ", strip=True)) for p in t.find_all(["p", "pre", "tr"]))
        return text_size - linked + paragraphs
    if selector:
        matches = soup.select(selector)
        if len(matches) != 1:
            raise ValueError("--selector phải chọn đúng một khối nội dung")
        root = matches[0]
    else:
        dedicated = soup.select('[itemprop="articleBody"], .entry-content, .post-content, .article-content, .post-body')
        semantic = soup.select("article, main, [role=main]")
        candidates = dedicated + semantic
        if candidates:
            best = max(candidates, key=score)
            # Prefer an explicit article body when it contains most of the
            # substantive content, excluding surrounding metadata/related cards.
            body = max(dedicated, key=score) if dedicated else None
            root = body if body is not None and score(body) >= 0.65 * score(best) else best
            # Same rule one level down: an <article> inside <main> that holds most of
            # the content is the report; the rest of <main> is related cards/events.
            while inner := [t for t in candidates if root in t.parents and score(t) >= 0.65 * score(root)]:
                root = max(inner, key=score)
            rivals = [t for t in candidates if t is not root and root not in t.parents and t not in root.parents
                      and score(t) >= 0.65 * score(root)]
            if rivals:
                warnings.append({"code": "multiple_content_roots", "detail": "Nhiều khối nội dung tương đương; kiểm tra hoặc dùng --selector"})
        else:
            candidates = soup.select("section, div")
            root = max(candidates, key=score) if candidates else (soup.body or soup)
            warnings.append({"code": "html_root_heuristic", "detail": "Thiếu article/main; khối nội dung được chọn bằng heuristic, cần rà"})
        # Thẻ article/main không bảo đảm chứa bài: có trang để bài ngoài <main> và <main> chỉ còn menu (10/10, một
        # trang blog ngoài tập đánh giá). Nếu khối đã chọn giữ ít hơn nửa chữ đoạn văn của trang thì chọn lại.
        page = soup.body or soup
        total = _prose(page)
        share = _prose(root) / total if total else 1.0
        if total >= _MIN_PAGE_PROSE and share < _ROOT_SHARE:
            root = _densest(page, total)
            warnings.append({"code": "html_root_fallback",
                             "detail": f"Khối article/main chỉ chứa {share:.0%} chữ đoạn văn của trang; đã chọn khối "
                                       f"chứa {_prose(root) / total:.0%}. Mở review.html kiểm tra, hoặc nhập lại với --selector"})
    _drop_related(root)
    # 15/10: <br> trong <pre>/<code> hay trong thẻ inline lồng nhau trước đây mất hẳn (get_text bỏ thẻ rỗng), nên danh sách IOC
    # một dòng một mục bị dính liền (vd `119.8.186[.]227longlog[.]cc`). Đổi mọi <br> thành xuống dòng trước khi đọc khối.
    for br in root.find_all("br"):
        br.replace_with("\n")
    blocks = []
    headings: list[tuple[int, str]] = []

    def add(text, kind, node, **extra):
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = text.strip() if kind == "mã/truy vấn" else re.sub(r"\s+", " ", text).strip()
        if not text:
            return
        blocks.append({"text": text, "kind": kind, "location": {"page": 0, "dom_path": paths.get(id(node), ""),
                       "section": " / ".join(t for _, t in headings), **extra}})

    def walk(node):
        if not isinstance(node, Tag):
            return
        name = node.name
        if re.fullmatch(r"h[1-6]", name or ""):
            level = int(name[1])
            text = node.get_text(" ", strip=True)
            while headings and headings[-1][0] >= level:
                headings.pop()
            headings.append((level, text))
            add(text, "tiêu đề", node)
        elif name == "pre":
            add(node.get_text(), "mã/truy vấn", node)
        elif name == "tr":
            cells = node.find_all(["th", "td"], recursive=False)
            codes = [p for c in cells for p in c.find_all("pre")]
            # A <pre> in a cell (e.g. a hunting query) stays a code block with its line breaks;
            # the rest of the row is still one table row.
            add(" | ".join(" ".join(s.strip() for s in c.find_all(string=True)
                                    if type(s) is NavigableString and not s.find_parent("pre") and s.strip())
                           for c in cells) if codes else
                " | ".join(c.get_text(" ", strip=True) for c in cells), "dòng bảng", node)
            for p in codes:
                add(p.get_text(), "mã/truy vấn", p)
            for img in node.find_all("img"):
                walk(img)
        elif name in ("img", "svg", "canvas", "iframe", "object", "embed", "video"):
            ref = node.get("src") or node.get("data-src") or node.get("data") or "(không có URL)"
            asset_ref = ref if ref.startswith(("data:", "https://", "http://")) else (urljoin(source, ref) if source.startswith(("http://", "https://"))
                                                            else str((Path(source).parent / ref).resolve()))
            ref = asset_ref if not ref.startswith("data:") else "(ảnh nhúng data URI)"
            label = node.get("alt", "")
            add(f"[CHƯA ĐỌC {name}] {ref}" + (f" — alt: {label}" if label else ""), "ảnh", node,
                extraction="unread", asset=asset_ref, asset_kind=name)
            warnings.append({"code": "unread_asset", "detail": f"Chưa đọc nội dung {name}; alt không phải OCR",
                             "dom_path": paths.get(id(node), "")})
        else:
            # Emit inline runs once; recurse into block boundaries, nested lists and images.
            boundary = {"p", "div", "section", "article", "main", "ul", "ol", "li", "blockquote", "table",
                        "thead", "tbody", "tfoot", "tr", "pre", "figure", "figcaption", "dl", "dt", "dd",
                        "img", "svg", "canvas", "iframe", "object", "embed", "video", *[f"h{i}" for i in range(1, 7)]}
            buffer = []
            def flush():
                add("".join(buffer), "đoạn văn", node)
                buffer.clear()
            for child in node.children:
                if isinstance(child, NavigableString):
                    # Comments are NavigableString too; only actual text nodes belong here.
                    if type(child) is NavigableString:
                        buffer.append(str(child))
                elif isinstance(child, Tag):
                    if child.name in boundary or child.find(list(boundary)):
                        flush()
                        walk(child)
                    else:
                        buffer.append("\n" if child.name == "br" else child.get_text())
            flush()
    walk(root)
    # Vùng trông như menu: ít khối chữ dài nhưng nhiều mục ngắn. Report ngắn nhưng là văn xuôi không bị báo; dòng bảng
    # (bảng IOC thường gồm toàn dòng ngắn) không tính là mục menu.
    long_blocks = sum(b["kind"] != "ảnh" and len(b["text"]) >= _LONG_BLOCK for b in blocks)
    menu_items = sum(b["kind"] == "đoạn văn" and len(b["text"]) < _MENU_ITEM for b in blocks)
    if long_blocks < _MIN_LONG_BLOCKS and menu_items >= _MIN_MENU_ITEMS:
        warnings.append({"code": "html_content_suspect",
                         "detail": f"Vùng đọc được có {long_blocks} khối chữ dài và {menu_items} mục ngắn, giống menu/chân "
                                   "trang; trang có thể cần JavaScript hoặc đã chọn nhầm vùng. Mở review.html; nếu sai "
                                   "thì nhập lại với --selector"})
    return blocks, warnings, title


def _inside(a, b) -> bool:
    return a[0] >= b[0] - 1 and a[1] >= b[1] - 1 and a[2] <= b[2] + 1 and a[3] <= b[3] + 1


def _pdf_order(blocks: list[dict], width: float) -> list[dict]:
    """Two-column heuristic with full-width blocks as section boundaries."""
    mid = width / 2
    box = lambda b: b["location"]["bbox"]
    wide = sorted([b for b in blocks if box(b)[0] < mid - 15 and box(b)[2] > mid + 15], key=lambda b: box(b)[1])
    narrow = [b for b in blocks if b not in wide]
    result = []
    for anchor in wide + [None]:
        top = box(anchor)[1] if anchor else float("inf")
        group = [b for b in narrow if box(b)[1] < top]
        narrow = [b for b in narrow if box(b)[1] >= top]
        result.extend(sorted(group, key=lambda b: (box(b)[0] >= mid, box(b)[1], box(b)[0])))
        if anchor:
            result.append(anchor)
    return result


def parse_pdf(raw: bytes) -> tuple[list[dict], list[dict], str]:
    try:
        import pdfplumber
    except ImportError as e:
        raise ValueError('Cài phụ thuộc đọc report: pip install -e ".[ingest]"') from e
    blocks, warnings = [], [{"code": "pdf_layout_review", "detail": "Thứ tự đọc PDF dùng heuristic; rà cột, bảng và đầu/chân trang trong bản nguồn"}]
    with pdfplumber.open(io.BytesIO(raw), laparams={"line_margin": 0.35}) as pdf:
        if len(pdf.pages) > MAX_PAGES:
            raise ValueError(f"PDF vượt giới hạn {MAX_PAGES} trang")
        title = str((pdf.metadata or {}).get("Title") or "")
        for page in pdf.pages:
            current = []
            def add(text, kind, bbox, **extra):
                if text.strip():
                    current.append({"text": text.strip(), "kind": kind,
                                    "location": {"page": page.page_number, "bbox": [round(float(x), 2) for x in bbox],
                                                 "section": f"Trang {page.page_number}", **extra}})
            tables = page.find_tables()
            table_boxes = [t.bbox for t in tables]
            for table in tables:
                for row in table.extract():
                    add(" | ".join(re.sub(r"\s+", " ", c or "") for c in row), "dòng bảng", table.bbox)
            normal_size = median([c["size"] for c in page.chars]) if page.chars else 0
            textboxes = page.objects.get("textboxhorizontal", [])
            for b in textboxes:
                bbox = (b["x0"], b["top"], b["x1"], b["bottom"])
                if any(_inside(bbox, tb) for tb in table_boxes):
                    continue
                chars = [c for c in page.chars if _inside((c["x0"], c["top"], c["x1"], c["bottom"]), bbox)]
                kind = "tiêu đề" if chars and median(c["size"] for c in chars) > normal_size * 1.2 else "đoạn văn"
                text = b.get("text", "").strip()
                if chars and sum("mono" in c.get("fontname", "").lower() or "courier" in c.get("fontname", "").lower() for c in chars) > len(chars) / 2:
                    kind = "mã/truy vấn"
                if any(bbox[0] < tb[2] and bbox[2] > tb[0] and bbox[1] < tb[3] and bbox[3] > tb[1] for tb in table_boxes):
                    warnings.append({"code": "pdf_table_overlap", "page": page.page_number,
                                     "detail": "Khối chữ giao bảng; có thể trùng nội dung, cần rà nguồn"})
                add(text, kind, bbox)
            if page.chars and not textboxes:
                add(page.extract_text() or "", "đoạn văn", (0, 0, page.width, page.height))
                warnings.append({"code": "pdf_text_fallback", "page": page.page_number, "detail": "Không xác định được khối; dùng chữ toàn trang"})
            if not page.chars:
                add("[CHƯA ĐỌC TRANG: không có lớp chữ]", "ảnh", (0, 0, page.width, page.height), extraction="unread")
                warnings.append({"code": "page_without_text", "page": page.page_number, "detail": "Trang trống hoặc quét; chưa OCR"})
            # A scanned page is one OCR target; do not duplicate its embedded image.
            for asset in page.images if page.chars else []:
                bbox = (asset["x0"], asset["top"], asset["x1"], asset["bottom"])
                add("[CHƯA ĐỌC ẢNH TRONG PDF]", "ảnh", bbox, extraction="unread")
                warnings.append({"code": "unread_asset", "page": page.page_number, "detail": "Ảnh chưa OCR, kể cả trang có lớp chữ"})
            if any(c.get("upright") is False for c in page.chars):
                warnings.append({"code": "rotated_text", "page": page.page_number, "detail": "Chữ xoay cần kiểm tra thứ tự và độ phủ"})
            blocks.extend(_pdf_order(current, page.width))
    return blocks, warnings, title


def render_review(manifest: dict, segments: list[dict], provenance: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    parts = ['<!doctype html><html lang="vi"><meta charset="utf-8">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">',
             '<title>Kiểm tra nội dung CTI report</title><style>body{max-width:1000px;margin:32px auto;padding:0 24px;font:16px/1.6 system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:16px}article{border-top:1px solid #ccc;padding:12px 0}.warn{color:#8b3100}small{overflow-wrap:anywhere}</style>',
             f'<h1>{esc(manifest["title"])}</h1><p>Nguồn: {esc(manifest["source"])}</p>',
             f'<p>Trạng thái: <strong>{esc(manifest["status"])}</strong>. Không có điểm chất lượng ngữ nghĩa.</p><ul class="warn">']
    for w in manifest["warnings"]:
        parts.append(f'<li>{esc(w)}</li>')
    parts.append('</ul><p>Cảnh báo có trường stage ghi lại lịch sử từng bước; trạng thái hiện tại nằm ở từng đoạn bên dưới. '
                 'Đối chiếu bản nguồn để xác nhận độ đầy đủ. Chữ OCR chưa rà bị cách ly khỏi TTP và IOC.</p>')
    for s in segments:
        p = provenance[s["ma_doan"]]
        display = {k: v for k, v in p.items() if k != "preview_data_uri"}
        picture = p.get("preview_data_uri", "")
        picture_tag = f'<img style="max-width:100%" alt="Ảnh nguồn OCR" src="{esc(picture)}">' if picture.startswith("data:image/png;base64,") else ""
        parts.append(f'<article id="{esc(s["ma_doan"])}"><h2>{esc(s["ma_doan"])} · {esc(s["loai"])}</h2>'
                     f'<small>{esc(display)}</small>{picture_tag}<pre>{esc(s["van_ban"])}</pre></article>')
    return "\n".join(parts) + "</html>"


def ingest(source: str, report_id: str, out: Path, selector: str | None = None) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", report_id):
        raise ValueError("Mã report chỉ gồm chữ, số, _ và -, tối đa 64 ký tự")
    out = Path(out)
    if out.exists():
        raise ValueError("Thư mục đầu ra đã tồn tại; dùng thư mục mới để giữ nguyên bản cũ")
    mime = ""
    if re.match(r"^https?://", source, re.I):
        raw, mime, resolved = fetch(source)
    else:
        path = Path(source)
        if path.suffix.lower() not in (".html", ".htm", ".pdf", ".png", ".jpg", ".jpeg"):
            raise ValueError("Hỗ trợ HTML/PDF/PNG/JPEG hoặc URL HTTP(S)")
        with path.open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
        resolved = str(path.resolve())
    if len(raw) > MAX_BYTES:
        raise ValueError("Report vượt giới hạn 25 MiB")
    if raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith(b"\xff\xd8\xff"):
        from PIL import Image
        kind = "png" if raw.startswith(b"\x89PNG") else "jpg"
        with Image.open(io.BytesIO(raw)) as im:
            if im.width * im.height > 25_000_000:
                raise ValueError("Ảnh vượt giới hạn 25 megapixel")
            size = [im.width, im.height]
            im.verify()
        blocks = [{"text": "[ẢNH CHƯA OCR]", "kind": "ảnh", "location": {"page": 1, "bbox": [0, 0, *size],
                   "section": "Ảnh nguồn", "asset_kind": "image", "extraction": "unread"}}]
        warnings, title = [{"code": "unread_asset", "detail": "Ảnh cần OCR và rà chữ trước khi trích thông tin"}], report_id
    elif raw.startswith(b"%PDF-"):
        if selector:
            raise ValueError("--selector chỉ áp dụng cho HTML")
        kind = "pdf"
        blocks, warnings, title = parse_pdf(raw)
    else:
        if mime and not any(x in mime.lower() for x in ("text/html", "application/xhtml")):
            raise ValueError(f"Content-Type không hỗ trợ: {mime}")
        if not re.search(br"<(?:!doctype\s+html|html|body|article|main|div|p|h[1-6])\b", raw[:65536], re.I):
            raise ValueError("Nội dung không phải HTML/PDF được hỗ trợ")
        kind = "html"
        blocks, warnings, title = parse_html(raw, resolved, selector)
    segments, provenance = [], {}
    for n, block in enumerate(blocks, 1):
        sid = f"{report_id}-{n:04d}"
        segments.append({"ma_doan": sid, "report": report_id, "loai": block["kind"], "van_ban": block["text"]})
        provenance[sid] = {"source_sha256": digest(raw), "extraction": "text", **block["location"]}
    readable = sum(s["loai"] not in ("ảnh", "tiêu đề") for s in segments)
    unread = sum(p["extraction"] == "unread" for p in provenance.values())
    if not readable:
        warnings.append({"code": "no_readable_content", "detail": "Không có nội dung để trích TTP; có thể trang cần JavaScript hoặc OCR"})
    alert = any(w.get("code") in SELECTION_ALERTS for w in warnings)
    status = ("blocked" if not readable else "needs_review" if alert else "partial" if unread
              else "needs_review" if warnings else "extracted")
    seg_bytes = ("\n".join(json.dumps(s, ensure_ascii=False) for s in segments) + "\n").encode("utf-8")
    prov_bytes = json.dumps(provenance, ensure_ascii=False, indent=2).encode("utf-8")
    manifest = {"schema_version": VERSION, "report_id": report_id, "title": title or report_id,
                "source": source, "resolved_source": resolved, "format": kind, "selector": selector,
                "source_file": f"source.{kind}", "source_sha256": digest(raw), "segments_sha256": digest(seg_bytes),
                "provenance_sha256": digest(prov_bytes), "status": status, "warnings": warnings,
                "segments": len(segments), "readable_segments": readable, "unread_blocks": unread,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "parser_versions": {("beautifulsoup4" if kind == "html" else "pdfplumber" if kind == "pdf" else "Pillow"):
                                     version("beautifulsoup4" if kind == "html" else "pdfplumber" if kind == "pdf" else "Pillow")}}
    manifest["normalization"] = "HTML: CRLF→LF; prose whitespace collapsed, code line breaks retained. PDF: extracted text retained."
    out.mkdir(parents=True, exist_ok=False)
    (out / f"source.{kind}").write_bytes(raw)
    (out / "segments.jsonl").write_bytes(seg_bytes)
    (out / "provenance.json").write_bytes(prov_bytes)
    write_json(out / "manifest.json", manifest)
    (out / "review.html").write_text(render_review(manifest, segments, provenance), encoding="utf-8")
    return manifest


def load_bundle(folder: Path) -> tuple[dict, list[dict], dict]:
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != VERSION:
        raise ValueError("Phiên bản report bundle không hỗ trợ")
    if manifest.get("format") not in ("html", "pdf", "png", "jpg"):
        raise ValueError("Định dạng report bundle không hợp lệ")
    for filename, key in (("segments.jsonl", "segments_sha256"), ("provenance.json", "provenance_sha256"),
                          (f"source.{manifest['format']}", "source_sha256")):
        if digest((folder / filename).read_bytes()) != manifest[key]:
            raise ValueError(f"Report bundle đã đổi: {filename}")
    segments = [json.loads(s) for s in (folder / "segments.jsonl").read_text(encoding="utf-8").splitlines() if s.strip()]
    provenance = json.loads((folder / "provenance.json").read_text(encoding="utf-8"))
    ids = [s["ma_doan"] for s in segments]
    if len(ids) != len(set(ids)) or set(ids) != set(provenance) or any(s["report"] != manifest["report_id"] for s in segments):
        raise ValueError("Mã đoạn/report/provenance không nhất quán")
    for name, expected in manifest.get("artifacts", {}).items():
        artifact = (folder / name).resolve()
        if not artifact.is_relative_to(folder.resolve()) or digest(artifact.read_bytes()) != expected:
            raise ValueError(f"Artifact OCR đã đổi hoặc đường dẫn không hợp lệ: {name}")
    return manifest, segments, provenance


def extraction_ready(segment: dict, provenance: dict) -> bool:
    """Only native text or an explicitly reviewed transcript enters extraction."""
    if segment["loai"] in ("ảnh", "tiêu đề"):
        return False
    p = provenance[segment["ma_doan"]]
    return p.get("extraction") == "text" or (p.get("extraction") == "ocr" and p.get("review_status") == "approved")
