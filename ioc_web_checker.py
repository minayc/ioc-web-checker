from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import UnexpectedAlertPresentException
from selenium.webdriver.support.ui import Select
from webdriver_manager.chrome import ChromeDriverManager
import time
import pandas as pd
from ioc_checker import extract_iocs_from_pdf
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import logging

#V&V
logging.basicConfig(
    filename="ioc_verification.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

CHECKERS = [
    {
        "name": "mcafee",
        "url": "https://sitelookup.mcafee.com/",
        "input": {"by": By.NAME, "value": "url"},
        "button": {"by": By.XPATH, "value": "//input[@type='submit' and @value='Check URL']"},
        "wait": 5,
        "result": {
            "type": "table",
            "table_index": 1,
            "row_idx": 1,
            "cell_map": {
                "url": 1,
                "status": 2,
                "categorization": 3,
                "trust": 4,
            }
        }
    },
    {
        "name": "trendmicro",
        "url": "https://global.sitesafety.trendmicro.com/result.php",
        "input": {"by": By.NAME, "value": "urlname"},
        "button": {"by": By.CSS_SELECTOR, "value": "input[type='submit']"},
        "wait": 5,
        "result": {
            "type": "trendmicro"  # <-- özel olarak ayarladık!
        }
    },
    {
        "name": "trellix",
        "url": "https://trustedsource.org/en/feedback/url?action=checksingle",
        "input": {"by": By.NAME, "value": "url"},
        "button": {"by": By.XPATH, "value": "//input[@type='submit' and @value='Check URL']"},
        "wait": 7,
        "result": {
            "type": "table",
            "table_index": 1,
            "row_idx": 1,
            "cell_map": {
                "url": 1,
                "status": 2,
                "categorization": 3,
                "trust": 4
            }
        }
    },
    {
        "name": "symantec",
        "url": "https://sitereview.symantec.com/#/"
    }
]

def universal_ioc_check(ioc, driver):
    results = {}
    for checker in CHECKERS:
        site_name = checker["name"]

        # Verification State
        verification = {
            "page_loaded": False,
            "input_found": False,
            "submit_clicked": False,
            "result_extracted": False
        }

        if site_name == "symantec":
            print(f"\n--- SYMANTEC MANUEL KONTROL ---")
            print(f"IOC: {ioc}")
            print(f"Manuel olarak şuradan kontrol edin: {checker['url']}", end="")
            kategori = input("Sonucu kopyalayıp buraya yapıştırabilirsiniz (veya Enter'a basın):\nKategori: ")
            risk = input("Risk (varsa): ")
            results[site_name] = {
                "category": kategori,
                "risk": risk,
                "verification": {
                    "manual": True
                }
            }
            continue

        driver.get(checker["url"])

        #Page load verification
        verification["page_loaded"] = True
        logging.info(f"[{site_name}] Page loaded successfully")
        time.sleep(3)

        if checker.get("type") == "manual":
            print("\n--- SYMANTEC MANUEL KONTROL ---")
            print(f"IOC: {ioc}")
            print(f"Manuel olarak şuradan kontrol edin: {checker['url']}")
            print("Sonucu kopyalayıp buraya yapıştırabilirsiniz (veya Enter'a basın):")
            manual_result = input("Kategori: ")
            results[site_name] = {"category": manual_result if manual_result else "Manuel kontrol gerekiyor"}
            continue

        if checker["name"] == "trellix":
            select_elem = driver.find_element(By.NAME, "product")
            select = Select(select_elem)
            select.select_by_visible_text("Trellix Endpoint Security Web Control")
            time.sleep(1)

        try:
            alert = driver.switch_to.alert
            print(f"[{site_name}] Alert çıktı, text: {alert.text}")
            alert.accept()
            time.sleep(1)
        except Exception:
            pass

        try:
            #Input field verification
            search_box = driver.find_element(checker["input"]["by"], checker["input"]["value"])
            verification["input_found"] = True
            logging.info(f"[{site_name}] Input field found")

            search_box.clear()
            search_box.send_keys(ioc)
            time.sleep(0.5)
            check_btn = driver.find_element(checker["button"]["by"], checker["button"]["value"])
            check_btn.click()

            #Submit action verification
            verification["submit_clicked"] = True
            logging.info(f"[{site_name}] Submit button clicked")
            time.sleep(checker["wait"])


            with open(f"{site_name}_result.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)

            # TrendMicro için özel extraction:
            if checker["result"]["type"] == "trendmicro":
                result_row = {}
                try:
                    # Safe/Dangerous/Suspicious/Untested status
                    result_row["status"] = driver.find_element(By.CSS_SELECTOR, ".labeltitleresult").text.strip()
                except Exception as e:
                    result_row["status"] = f"error: {e}"

                try:
                    categories = driver.find_elements(By.CSS_SELECTOR, ".labeltitlesmallresult")
                    result_row["categories"] = ", ".join([cat.text.strip() for cat in categories if cat.text.strip()])
                except Exception as e:
                    result_row["categories"] = f"error: {e}"

                # Result extraction verification
                verification["result_extracted"] = True
                logging.info(f"[{site_name}] Result extracted successfully")

                result_row["verification"] = verification
                results[site_name] = result_row

            elif checker["result"]["type"] == "table":
                tables = driver.find_elements(By.TAG_NAME, "table")
                result_row = {}
                try:
                    if len(tables) > checker["result"]["table_index"]:
                        rows = tables[checker["result"]["table_index"]].find_elements(By.TAG_NAME, "tr")
                        for row_idx, row in enumerate(rows):
                            cells = row.find_elements(By.TAG_NAME, "td")
                            if row_idx == checker["result"]["row_idx"] and len(cells) >= max(checker["result"]["cell_map"].values())+1:
                                for key, idx in checker["result"]["cell_map"].items():
                                    result_row[key] = cells[idx].text.strip()
                                break
                    # Result extraction verification
                    verification["result_extracted"] = True
                    logging.info(f"[{site_name}] Result extracted successfully")

                except Exception as e:
                    result_row = {"error": str(e)}

                result_row["verification"] = verification
                results[site_name] = result_row

        except UnexpectedAlertPresentException as e:
            logging.error(f"[{site_name}] Unexpected alert: {e}")

            try:
                driver.save_screenshot(f"{site_name}_alert_failure.png")
            except Exception:
                pass

            results[site_name] = {
                "status": "FAILED",
                "reason": "UNEXPECTED_ALERT",
                "verification": verification
            }
        except Exception as e:

            logging.error(f"[{site_name}] Exception occurred: {e}")

            try:
                driver.save_screenshot(f"{site_name}_failure.png")
                logging.info(f"[{site_name}] Screenshot captured for failure")
            except Exception:
                logging.warning(f"[{site_name}] Screenshot capture failed")

            results[site_name] = {
                "status": "FAILED",
                "reason": "EXCEPTION",
                "verification": verification
            }
        time.sleep(2)
    return results


def write_results_to_pdf(df, output_path):
    # Validation check before PDF generation
    if df.empty:
        raise ValueError("Validation failed: No IOC results to include in report")

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elems = []
    elems.append(Paragraph("IOC Checker Raporu", styles['Title']))
    elems.append(Spacer(1, 12))

    header = [Paragraph(col, styles['Heading4']) for col in df.columns]
    data = [header]
    for _, row in df.iterrows():
        row_cells = []
        for col in df.columns:
            cell = row[col]
            lines = []
            if isinstance(cell, dict):
                # McAfee ve Trellix klasik extraction
                if col in ("mcafee", "trellix"):
                    if cell.get("status"):
                        lines.append(f"Status: {cell['status']}")
                    if cell.get("categorization"):
                        lines.append(f"Categorization: {cell['categorization']}")
                    if cell.get("trust"):
                        lines.append(f"Trust: {cell['trust']}")
                # TrendMicro yeni extraction!
                elif col == "trendmicro":
                    if cell.get("status"):
                        lines.append(f"Status: {cell['status']}")
                    if cell.get("categories"):
                        lines.append(f"Categories: {cell['categories']}")
                elif col == "symantec":
                    if cell.get("category"):
                        lines.append(f"Category: {cell['category']}")
                text = "\n".join(lines) or ""
                row_cells.append(Paragraph(text, styles['Normal']))
            else:
                row_cells.append(Paragraph(str(cell), styles['Normal']))
        data.append(row_cells)
    table = Table(data, repeatRows=1, colWidths=[80, 100, 100, 100, 100])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#d3d3d3")),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.black),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('ALIGN',      (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ('FONTSIZE',   (0,0), (-1,-1), 8),
    ]))
    elems.append(table)
    doc.build(elems)


def validate_results(df):
    return not df.empty and "ioc" in df.columns

if __name__ == "__main__":
    df_iocs = extract_iocs_from_pdf("IndicatorOfCompromises1.pdf")
    ioc_list = df_iocs["ioc"].dropna().tolist()

    options = Options()
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )

    all_results = []
    for ioc in ioc_list:
        print(f"Checking: {ioc}")
        res = universal_ioc_check(ioc, driver)
        all_results.append({
            "ioc": ioc,
            **res
        })

    driver.quit()

    df_results = pd.DataFrame(all_results)
    df_results.to_csv("ioc_results.csv", index=False)
    print("Tüm sonuçlar ioc_results.csv dosyasına kaydedildi.")

    assert validate_results(df_results), "Validation failed: Result structure invalid"
    write_results_to_pdf(df_results, "ioc_results.pdf")
    print("PDF raporu oluşturuldu: ioc_results.pdf")




