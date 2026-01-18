import pdfplumber
import pandas as pd
import re
from urlextract import URLExtract

#Validating signaling have been added
def sanitize_ioc(ioc: str) -> str:
    if not ioc or not isinstance(ioc, str):
        return ""

    ioc = ioc.replace('\n', '').replace('\r', '').strip()

    ioc = re.sub(
        r'^(hxxps?):\/\/?',
        lambda m: 'https://' if m.group(1).endswith('s') else 'http://',
        ioc, flags=re.IGNORECASE
    )
    ioc = re.sub(
        r'^(hxxps?):',
        lambda m: 'https:' if m.group(1).endswith('s') else 'http:',
        ioc, flags=re.IGNORECASE
    )
    ioc = re.sub(
        r'(\[\.]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})',
        '.', ioc, flags=re.IGNORECASE
    )
    ioc = re.sub(r'(\[at\]|\(at\)|\{at\})', '@', ioc, flags=re.IGNORECASE)
    ioc = re.sub(r'[\[\]\{\}\(\)]', '', ioc)
    ioc = re.sub(r'\.{2,}', '.', ioc)

    return ioc.strip('.').strip()


def extract_iocs_from_pdf(pdf_path: str) -> pd.DataFrame:

    iocs = []
    all_indicators = []

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            for table in page.extract_tables():
                header = table[0]
                for row in table[1:]:
                    row_dict = dict(zip(header, row))

                    raw = row_dict.get('Indicator') or row_dict.get('SHA256 Hash')
                    if not raw:
                        continue
                    raw = raw.replace('\n', '').replace('\r', '').strip()

                    ioc_type = (
                        row_dict.get('Indicator Type')
                        or ('Hash' if row_dict.get('SHA256 Hash') else None)
                    )

                    clean = sanitize_ioc(raw)
                    all_indicators.append(clean)
                    iocs.append({
                        'ioc': clean,
                        'type': ioc_type,
                        'desc': row_dict.get('Description', ''),
                        'first_seen': row_dict.get('First Seen', '')
                    })

    text = "\n".join(all_indicators)
    extractor = URLExtract()
    urls = extractor.find_urls(text)

    not_url_iocs = [item for item in iocs if not extractor.has_urls(item['ioc'])]

    def clean_url(u: str) -> str:
        return u.replace('\n', '').replace('\r', '').replace(' ', '')

    result_iocs = []
    for u in urls:
        result_iocs.append({
            'ioc': clean_url(u),
            'type': 'URL',
            'desc': '',
            'first_seen': ''
        })
    result_iocs.extend(not_url_iocs)

    return pd.DataFrame(result_iocs)


def classify_ioc(ioc: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IP"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "HASH"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "URL"
    return "UNKNOWN"



if __name__ == "__main__":
    df = extract_iocs_from_pdf("IndicatorOfCompromises1.pdf")
    ioc_list = df["ioc"].dropna().tolist()

    with open("extracted_iocs.txt", "w", encoding="utf-8") as f:
        for ioc in ioc_list:
            f.write(ioc + "\n")

    print("IOC'ler 'extracted_iocs.txt' dosyasına kaydedildi.")


