"""Huấn luyện lại rcATT (Legoy và cộng sự, 2020) đúng cấu hình gốc, bỏ report trùng tập đánh giá, rồi dự đoán kỹ thuật.

Chạy bằng venv riêng có scikit-learn, pandas, nltk (không thuộc phụ thuộc của repo), không import ``cti_hunt``:

    <venv rcATT>/python.exe -I scripts/rcatt_huan_luyen_du_doan.py --rcatt <thư mục repo rcATT> --van-ban <thư mục .txt>
        --nltk-data <thư mục nltk_data> --bo "Dissecting One of APT29" --out <thư mục ra>

Vì sao viết lại thay vì gọi mã của rcATT:
- mã gốc dùng ``DataFrame.append`` (pandas đã bỏ) và nạp mô hình/tham số hậu xử lý bằng ``joblib.load`` (pickle: nạp là chạy
  mã trong tệp); viết lại thì không nạp pickle nào;
- phải bỏ được report trùng tập đánh giá khỏi dữ liệu học (POSHSPY nằm trong 1.490 report của rcATT).

Giữ nguyên của rcATT (``classification_tools/__init__.py`` hàm ``train``, ``preprocessing.py``, commit f82f7fd): làm sạch
văn bản ``clean_text``; dữ liệu ``training_data_original.csv`` đọc ISO-8859-1; mô hình kỹ thuật = TF-IDF (tách từ nltk,
stemming Snowball, stop word tiếng Anh của nltk + danh sách bổ sung của rcATT, min_df=2, max_df=0.99) → chọn 50% đặc trưng
theo chi2 → một LinearSVC (l2, squared hinge, dual=False, class_weight=balanced) cho mỗi kỹ thuật. Không giữ: bước hậu xử
lý tùy chọn (hanging node / confidence propagation), vì tham số của nó nằm trong tệp pickle; ghi rõ trong kết quả. Văn bản
cần dự đoán đọc UTF-8 (rcATT gốc đọc ISO-8859-1 rồi đổi ký tự ngoài ASCII thành mã escape).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path

# Sao nguyên văn từ rcATT preprocessing.clean_text (giữ cả các mẫu regex lỗi của bản gốc để hành vi giống hệt).
_SUBS = [
    ("\r\n", "\t"), (r"what's", "what is "), (r"\'s", " "), (r"\'ve", " have "), (r"can't", "can not "),
    (r"n't", " not "), (r"i'm", "i am "), (r"\'re", " are "), (r"\'d", " would "), (r"\'ll", " will "),
    (r"\'scuse", " excuse "),
    ('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.)\\{3\\}(?:25[0-5] |2[0-4][0-9]|[01]?[0-9][0-9]?)(/([0-2][0-9]|3[0-2]|[0-9]))?', "IPv4"),
    ("\b(CVE\\-[0-9]{4}\\-[0-9]{4,6})\b", "CVE"),
    ("\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\\.[a-z]+)\b", "email"),
    ("\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\b", "IP"),
    ("\b([a-f0-9]{32}|[A-F0-9]{32})\b", "MD5"),
    ("\b((HKLM|HKCU)\\[\\A-Za-z0-9-_]+)\b", "registry"),
    ("\b([a-f0-9]{40}|[A-F0-9]{40})\b", "SHA1"),
    ("\b([a-f0-9]{64}|[A-F0-9]{64})\b", "SHA250"),
    ("http(s)?:\\[0-9a-zA-Z_\\.\\-\\]+.", "URL"),
    ("CVE-[0-9]{4}-[0-9]{4,6}", "vulnerability"),
    ("[a-zA-Z]{1}:\\[0-9a-zA-Z_\\.\\-\\]+", "file"),
    ("\b[a-fA-F\\d]{32}\b|\b[a-fA-F\\d]{40}\b|\b[a-fA-F\\d]{64}\b", "hash"),
    ("x[A-Fa-f0-9]{2}", " "), ("\\W", " "), ("\\s+", " "),
]
EXTRA_STOP = ["'ll", "'re", "'ve", "ha", "wa", "'d", "'s", "abov", "ani", "becaus", "befor", "could", "doe", "dure",
              "might", "must", "n't", "need", "onc", "onli", "ourselv", "sha", "themselv", "veri", "whi", "wo", "would",
              "yourselv"]


def clean_text(text: str) -> str:
    text = str(text).lower()
    for pat, rep in _SUBS:
        text = re.sub(pat, rep, text)
    return text.strip(" ")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rcatt", required=True, help="thư mục repo rcATT (đọc classification_tools/data/*.csv)")
    ap.add_argument("--van-ban", required=True, help="thư mục .txt + danh_sach.json do do_ttp_rcatt_mitre.py xuat ghi")
    ap.add_argument("--nltk-data", required=True)
    ap.add_argument("--bo", action="append", default=[], help="chuỗi trong 200 ký tự đầu của dòng dữ liệu học cần bỏ")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    import nltk
    nltk.data.path.insert(0, a.nltk_data)
    import pandas as pd
    import sklearn
    from nltk import word_tokenize
    from nltk.corpus import stopwords
    from nltk.stem.snowball import EnglishStemmer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.feature_selection import SelectPercentile, chi2
    from sklearn.multiclass import OneVsRestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.svm import LinearSVC

    stemmer = EnglishStemmer()

    def stem_tokenizer(doc: str) -> list[str]:
        return [stemmer.stem(t) for t in word_tokenize(doc)]

    csv_path = Path(a.rcatt) / "classification_tools" / "data" / "training_data_original.csv"
    df = pd.read_csv(csv_path, encoding="ISO-8859-1")
    head = df["Text"].astype(str).str[:200]
    drop = [i for i in df.index if any(s in head[i] for s in a.bo)]
    removed = [{"dong": int(i), "dau": head[i][:150]} for i in drop]
    df = df.drop(index=drop).reset_index(drop=True)
    tech_cols = [c for c in df.columns if c.startswith("T1")]
    y = df[tech_cols].astype(int)
    X = df["Text"].map(clean_text)

    stop = stopwords.words("english") + EXTRA_STOP
    model = Pipeline([
        ("tfidf", TfidfVectorizer(tokenizer=stem_tokenizer, stop_words=stop, min_df=2, max_df=0.99)),
        ("selection", SelectPercentile(chi2, percentile=50)),
        ("classifier", OneVsRestClassifier(LinearSVC(penalty="l2", loss="squared_hinge", dual=False, max_iter=1000,
                                                     class_weight="balanced"), n_jobs=1)),
    ])
    t0 = time.time()
    model.fit(X, y)
    train_s = time.time() - t0

    van_ban = Path(a.van_ban)
    danh_sach = json.loads((van_ban / "danh_sach.json").read_text(encoding="utf-8"))
    out = {"meta": {"rcatt_csv_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
                    "dong_du_lieu_hoc": int(len(df)), "dong_bo": removed, "so_ky_thuat": len(tech_cols),
                    "ky_thuat_khong_co_mau_duong": [c for c in tech_cols if int(y[c].sum()) == 0],
                    "sklearn": sklearn.__version__, "pandas": pd.__version__, "nltk": nltk.__version__,
                    "giay_huan_luyen": round(train_s, 1), "hau_xu_ly": "không dùng (tham số gốc nằm trong pickle)"},
           "du_doan": {}}
    for row in danh_sach:
        text = (van_ban / row["tep"]).read_text(encoding="utf-8")
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == row["sha256"], row["tep"]
        x = pd.Series([clean_text(text)])
        pred = model.predict(x)[0]
        score = model.decision_function(x)[0]
        ma = [c for c, v in zip(tech_cols, pred) if v]
        out["du_doan"][Path(row["tep"]).stem] = {"report": row["report"], "ma": ma,
                                                 "diem": {c: round(float(s), 4) for c, s in zip(tech_cols, score)}}
        print(f"{row['report']}: {len(ma)} kỹ thuật")
    Path(a.out).mkdir(parents=True, exist_ok=True)
    (Path(a.out) / "du_doan_rcatt.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"bỏ {len(removed)} dòng: {removed}; học trên {len(df)} report trong {train_s:.0f} giây")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
