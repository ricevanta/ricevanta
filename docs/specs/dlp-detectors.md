# DLP detectors

The built-in validators of `ricevanta-scan`, the first-party recognizers for Vietnamese personal identifiers and financial data, the `dictionary` pack format, record detection, how match confidence combines into a classification, and the redaction masks evidence uses. The scanner, fingerprints, the classification catalogue and channel decisions are in `../design/dlp.md`; the `pii`, `secrets` and `yara` pack formats are in `rule-adapters.md` sections 5 to 7. Decisions: DLP-02, DLP-03 and DLP-06. Formats marked "verify" rest on secondary sources.

## 1. Validators

A recognizer names at most one validator and any number of invalidators (`rule-adapters.md` section 6). The catalogue is closed and implemented in the scanner; validators that need tables read them from the pack's `tables/` directory, so a table change (a province merger, a new card range) ships as a pack version, not a scanner release.

| Validator | Check |
|---|---|
| `luhn` | ISO/IEC 7812-1 mod 10 over the digits |
| `iin_known` | Prefix and length against the pack's issuer table (section 3) |
| `iban_mod97` | ISO 13616 mod 97 equals 1, length per country table |
| `emvco_crc` | CRC-16/CCITT-FALSE of an EMVCo QR payload against its tag `63` |
| `vn_personal_id` | Section 2.1 |
| `vn_cmnd` | Section 2.2 |
| `vn_tax_code` | Section 2.3 |
| `vn_mobile` | Section 2.5 |
| `vn_bhyt_legacy` | Section 2.6 |
| `not_degenerate` (invalidator) | Rejects one repeated digit and ascending or descending runs over the whole value |
| `not_listed` (invalidator) | Rejects values in the pack's or the organization's exclusion list: test card numbers, the organization's own tax code, documentation samples |

## 2. Vietnamese personal identifiers

Every recognizer has a bare pattern with a low score and a labelled pattern that includes the identifier's name before the value (`CCCD`, `căn cước`, `CMND`, `MST`, `hộ chiếu` and their spellings without diacritics) with a high score, so one labelled value reaches the default `minConfidence` of 0.9 and bare values need context words or a count (section 6). Digits may be separated by spaces, dots or hyphens in groups; the validator sees digits only. Values adjacent to further digits or letters do not match.

| Recognizer | Bare pattern | Validator | Bare score | Labelled score | Context words (excerpt) | Category |
|---|---|---|---|---|---|---|
| `vn-personal-id` | 12 digits | `vn_personal_id` | 0.6 | 0.95 | căn cước, CCCD, số định danh, CMND, citizen ID | `pii.vn.basic` |
| `vn-cmnd` | 9 digits | `vn_cmnd` | 0.3 | 0.9 | CMND, CMT, chứng minh nhân dân | `pii.vn.basic` |
| `vn-tax-code` | 10 digits; 10 digits, hyphen, 3 digits | `vn_tax_code` | 0.3; 0.7 | 0.95 | MST, mã số thuế, tax code | `pii.vn.basic` for individuals; organization codes are not personal data and carry the category only with a personal name field in the same record |
| `vn-passport` | One uppercase letter and 7 digits (verify) | | 0.1 | 0.9 | hộ chiếu, passport, số HC | `pii.vn.basic` |
| `vn-phone` | Mobile: `0`, `84` or `+84`, then 9 digits; fixed: `0` or `+84`, then `2` and 9 digits | `vn_mobile` for mobile | 0.5; 0.3 | 0.9 | điện thoại, ĐT, SĐT, di động, Zalo, phone | `pii.vn.basic` |
| `vn-social-insurance` | 10 digits | | 0.1 | 0.9 | mã số BHXH, sổ BHXH, BHXH, mã thẻ BHYT | `pii.vn.basic` |
| `vn-health-insurance-legacy` | 2 uppercase letters, 1 digit 1 to 5, 2 digits, 10 digits | `vn_bhyt_legacy` | 0.7 | 0.95 | thẻ BHYT, bảo hiểm y tế | `pii.vn.basic` |
| `email` | RFC 5322 address subset | | 0.5 | 0.9 | email, thư điện tử | `pii.vn.basic` |

### 2.1 Personal identification number (căn cước, CCCD)

12 digits: a 3-digit province code of birth registration, one century-and-gender digit, the last two digits of the birth year and six random digits. No check digit. The province code is the national administrative unit code with a leading zero (001 Hà Nội to 096 Cà Mau, 63 codes with gaps; a merged province keeps the code of its seat, so the list also covers numbers issued after the 2025 mergers); the century-and-gender digit is 0 and 1 for 1900 to 1999 (male, female), 2 and 3 for 2000 to 2099, and so on in pairs. Both tables are public and ship in the pack. The checks raise confidence and never reject on their own:

| Positions | Meaning | Check |
|---|---|---|
| 1 to 3 | Province code of birth registration, or a country code for registration abroad | In the pack's `vn-province-codes` or `vn-country-codes` table |
| 4 | Century and gender | 0 to 3 accepted |
| 5 to 6 | Last two digits of the birth year | With position 4, the year is not after the scan date |
| 7 to 12 | Random | `not_degenerate` over the whole number |

A random 12-digit string passes with a probability of roughly 2 %, which is why the bare score is 0.6 and counts raise it (section 6). A labelled match classifies even when the check fails.

### 2.2 CMND (9 digits)

The 9-digit identity card number, still in circulation. The first two digits are a province code (verify); `vn_cmnd` checks them against the pack's `vn-cmnd-prefixes` table. Without a check digit the bare score is 0.3.

### 2.3 Tax codes

Organizations and persons without a personal identification number hold a 10-digit code; dependent units a 13-digit code written as the 10-digit parent code, a hyphen and 3 digits. Individuals use their 12-digit personal identification number as tax code, which `vn-personal-id` detects; a labelled `MST` before 12 digits uses the `vn_personal_id` validator. `vn_tax_code` checks the shape only: 10 digits, or 10 digits with a suffix 001 to 999. A Vietnamese mobile number is also 10 digits starting with 0, so the bare 10-digit score is 0.3 and a value matching both recognizers keeps the higher labelled match only.

### 2.4 Passport

An ordinary passport number is one uppercase letter and seven digits (verify); the pattern alone matches many reference numbers, so only labelled or context-raised matches classify.

### 2.5 Phone numbers

Mobile numbers have 10 digits, starting with `03`, `05`, `07`, `08` or `09`, written with `0` or with `84` and `+84` in place of it; fixed lines start with `02` and have 11 digits (verify). `vn_mobile` checks the three-digit prefix against the pack's carrier table.

### 2.6 Social and health insurance

The social insurance number has 10 digits with no published check digit. Health insurance cards issued under Decision 1666/QĐ-BHXH show that 10-digit number as the card code; cards under Decision 1351/QĐ-BHXH carry 15 characters: a 2-letter beneficiary group code, a benefit level digit 1 to 5, a 2-digit province code and the 10-digit number (verify). `vn_bhyt_legacy` checks the group code and province against pack tables.

## 3. Financial data

| Recognizer | Pattern | Validator | Bare score | With context or label | Category |
|---|---|---|---|---|---|
| `card-pan` | 13 to 19 digits in groups | `luhn`, `iin_known` | 0.7 | 0.95 (thẻ, số thẻ, card, Visa, Mastercard, JCB, NAPAS, ATM) | `financial.card` |
| `card-cvv` | 3 or 4 digits, labelled only (CVV, CVC, CVV2, mã bảo mật) or within 50 characters after a PAN | | | 0.9 | `financial.card` |
| `card-expiry` | `MM/YY` or `MM/YYYY`, labelled (hết hạn, HSD, exp, valid thru) or within 50 characters of a PAN | | | 0.8 | `financial.card` |
| `card-track` | Track 1 `%B<PAN>^<name>^<YYMM>…`, Track 2 `;<PAN>=<YYMM>…` | `luhn` on the PAN | 0.99 | | `financial.card` |
| `bank-account` | Labelled only: số tài khoản, STK, số TK, tài khoản số, account number, then 6 to 19 digits | `not_degenerate` | | 0.85; 0.95 with a bank name from the `vn-banks` dictionary in the window | `financial.account` |
| `iban` | 2 letters, 2 digits, 11 to 30 alphanumerics | `iban_mod97` | 0.9 | 0.95 | `financial.account` |
| `swift-bic` | 4 letters, country, 2 alphanumerics, optional 3 | | 0.3; 0.5 for country `VN` | 0.85 (SWIFT, BIC) | `financial.account` |
| `vietqr-payload` | EMVCo payload text starting `000201` that contains the NAPAS identifier `A000000727` | `emvco_crc` | 0.9 | | `financial.account` |
| `finance-vocabulary` | `finance-vn` dictionary: sao kê, lịch sử giao dịch, số dư, dư nợ, hạn mức tín dụng, khoản vay, điểm tín dụng, statement, balance | | | Classifies only with at least 3 distinct terms and a card, account or personal identification match in the same object | `financial.account` |

The `iin_known` table holds Visa (4), Mastercard (51 to 55, 2221 to 2720), American Express (34, 37; 15 digits), JCB (3528 to 3589), UnionPay (62), Discover (6011, 65) and NAPAS domestic cards (9704; 16 or 19 digits). NAPAS cards are checked with `luhn` like the others (verify that every 9704 range follows ISO/IEC 7812-1; a range that does not is marked length-only in the table). Bank account numbers have bank-specific lengths and no national check digit, so they classify only when labelled.

## 4. `dictionary` packs

A `RulePack` of format `dictionary` holds YAML term lists:

```yaml
lists:
  - id: vn-state-secret-markings
    category: confidential.marked
    case: sensitive            # sensitive | insensitive
    diacritics: sensitive      # insensitive folds Vietnamese diacritics and đ to d
    whole_word: true
    min_distinct: 1
    min_total: 1
    score: 0.6
    terms: [ "TUYỆT MẬT", "TỐI MẬT", "MẬT" ]
```

Terms compile into one `aho-corasick` automaton per pack over the normalized text. `min_distinct` and `min_total` set how many different terms and how many occurrences an object needs; `score` is the match confidence before section 6. `diacritics: insensitive` serves terms users type without diacritics, such as project code names, and is refused for terms of three characters or fewer, which would match common syllables. First-party lists: `vn-state-secret-markings` and `confidential-markings` (CONFIDENTIAL, INTERNAL ONLY, NỘI BỘ, MẬT stamped in headers, raised to 0.9 by the `confidential-docs` YARA rules that find the marking in a header or footer), `vn-banks` (bank names and abbreviations), `finance-vn` and `pii-field-names` (section 5).

## 5. Records

Customer information is recognized as records, since names and addresses have no pattern and named-entity recognition is not in the scanner (`rule-adapters.md` section 6, `ner_required`). A record is a spreadsheet row, a CSV or TSV line, a JSON object in an array, or a text line. A header cell that matches the `pii-field-names` dictionary (Họ và tên, Ngày sinh, Giới tính, Địa chỉ, Số CCCD, SĐT, Email, Số tài khoản, Mã khách hàng and their spellings without diacritics and English forms) gives its column that field type and acts as a context word for every cell in it. A record counts when it holds at least two distinct personal field types, of which at least one is a validated identifier from sections 2 and 3. `customer.records` classifies an object with at least 10 records at confidence 0.95 and 100 or more at 0.99; `match.count` carries the record count. Both thresholds are pack values.

## 6. Confidence

Per match: the score of the pattern that matched; a failing validator or a matching invalidator drops the match; a context word within the 5 words before the match raises the score by 0.35 with a floor of 0.4 (`rule-adapters.md` section 6), capped at 0.99. Matches in OCR text are lowered by 0.1, since OCR recall and precision on photos are unmeasured.

Per object and category: matches are deduplicated by normalized value, and the category confidence is 1 - Π(1 - sᵢ) over the distinct values, capped at 0.99, so many weak matches classify bulk data while one weak match does not (five bare personal identification numbers at 0.6 give 0.99). Fingerprint, dictionary, YARA and extension classifier matches enter the same formula with their own scores. `match.confidence` is the highest category confidence, `match.categories` lists each category with its confidence and distinct count, `match.count` is the distinct count of the deciding category, and `match.classification` is the label of `../design/dlp.md` section 5.1. The formula is deterministic, so the same content gives the same result on every endpoint and in server-side fixtures.

## 7. Redaction masks

Evidence snippets (DLP-02) mask every detector match inside the snippet window, not only the triggering one:

| Type | Mask |
|---|---|
| Personal identification number, CMND, tax code, passport, phone, social and health insurance numbers, bank account | Every character except the last 3 replaced by `*`, separators kept |
| Card number | Every digit except the last 4 replaced by `*` (PCI DSS permits the first six and last four; Ricevanta keeps fewer) |
| CVV, track data | Replaced by `[REDACTED]` with no characters kept, since sensitive authentication data is not stored |
| Secrets | First 4 characters, `…` and the length, for example `AKIA…(20)`; private key blocks become `[PRIVATE KEY]` |
| Email | First character of the local part, `***@` and the domain |
| Dictionary terms and markings | Not masked |
| Fingerprint matches | No snippet: evidence carries the set uid, the registered document's index and the shared count, and the console resolves the name, because the snippet would disclose the registered text |

Any other run of 6 or more digits inside the window keeps only its last 3 digits. The window is at most 200 characters, centred on the match and cut at whitespace.

## 8. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: labelled patterns let one identifier with its name classify while bare numbers need corroboration; tables in packs follow administrative changes without a scanner release; record detection finds customer lists without named-entity recognition; one deterministic formula gives identical results everywhere.

Trade-offs: bare 9- and 10-digit numbers classify only with context or volume, so a single unlabelled CMND or social insurance number in prose is missed; the noisy-OR combination can raise confidence on content with many unrelated weak matches, which the per-category deduplication and validators limit.

Dependencies: `regex`, `aho-corasick` and the pack tables; no further library.

Limits: structural checks raise confidence only, so a labelled value classifies even with a wrong table entry; names and addresses are found only through record headers; QR codes inside images are not decoded, so a VietQR payload is found only as text.

Alternatives considered: named-entity recognition models on the endpoint (rejected: model size against the scanner cap and no Vietnamese model with confirmed license; an extension `classifier` can add one); a fixed score per recognizer without labelled patterns (rejected: forces a choice between missing labelled single values and flagging every 9-digit number); hard-coded code tables (rejected: an administrative change would need a release).

## Sources

- Personal identification number, published tables: [luatvietnam.vn, the 12 digits with the province and century tables](https://luatvietnam.vn/tin-phap-luat/y-nghia-12-chu-so-tren-the-can-cuoc-cong-dan-230-17670-article.html); [baoquocte.vn, 63 province codes](https://baoquocte.vn/tra-cuu-ma-63-tinh-thanh-tren-the-can-cuoc-cong-dan-232141.html).
- Tax codes, secondary: [thuvienphapluat.vn on Circular 86/2024/TT-BTC](https://thuvienphapluat.vn/ma-so-thue/phap-luat-thue/so-cccd-la-ma-so-thue-duy-nhat-cua-ca-nhan-co-dung-khong-337213-225632.html).
- Health insurance, secondary: [Decision 1666/QĐ-BHXH](https://thuvienphapluat.vn/van-ban/Bao-hiem/Quyet-dinh-1666-QD-BHXH-2020-mau-the-bao-hiem-y-te-458650.aspx), [Decision 1351/QĐ-BHXH](https://caselaw.vn/van-ban-phap-luat/150943-quyet-dinh-so-1351-qd-bhxh-ngay-16-11-2015-ve-ma-so-ghi-tren-the-bao-hiem-y-te-do-tong-giam-doc-bao-hiem-xa-hoi-viet-nam-ban-hanh).
- Passports, secondary: [Circular 31/2023/TT-BCA summary](https://luatvietnam.vn/tin-van-ban-moi/ap-dung-mau-ho-chieu-moi-tu-ngay-15-8-2023-186-95087-article.html).
- Presidio context enhancement defaults: [lemma_context_aware_enhancer.py](https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/context_aware_enhancers/lemma_context_aware_enhancer.py).
