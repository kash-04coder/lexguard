import html
from datetime import datetime


SCHEDULE_PAGE_1 = """THE SCHEDULE
[See section 63(4)(c)]
CERTIFICATE
PART A
(To be filled by the Party)
I, _____________________ (Name), Son/daughter/spouse of ___________________
residing/employed at __________________________ do hereby solemnly affirm and
sincerely state and submit as follows:
I have produced electronic record/output of the digital record taken from the following
device/digital record source (tick mark):
Computer / Storage Media DVR Mobile Flash Drive
CD/DVD Server Cloud Other
Other: ________________________________________
Make & Model: _______________ Color: _______________
Serial Number: _______________
IMEI/UIN/UID/MAC/Cloud ID_____________________ (as applicable)
and any other relevant information, if any, about the device/digital record____(specify).
The digital device or the digital record source was under the lawful control for regularly
creating, storing or processing information for the purposes of carrying out regular
activities and during this period, the computer or the communication device was working
properly and the relevant information was regularly fed into the computer during the
ordinary course of business. If the computer/digital device at any point of time was not
working properly or out of operation, then it has not affected the electronic/digital
record or its accuracy. The digital device or the source of the digital record is:
Owned Maintained Managed Operated
by me (select as applicable).
I state that the HASH value/s of the electronic/digital record/s is _________________,
obtained through the following algorithm:
SHA1:
SHA256:
MD5:
Other__________________ (Legally acceptable standard)
(Hash report to be enclosed with the certificate)
(Name and signature)
Date (DD/MM/YYYY): _____
Time (IST): ________hours (In 24 hours format)
Place: ____________
THE GAZETTE OF INDIA EXTRAORDINARY [Part II"""

SCHEDULE_PAGE_2 = """SEC. 1] THE GAZETTE OF INDIA EXTRAORDINARY
PART B
(To be filled by the Expert)
I, ____________________ (Name), Son/daughter/spouse of _____________________
residing/employed at _________________________ do hereby solemnly affirm and
sincerely state and submit as follows:
The produced electronic record/output of the digital record are obtained from the following
device/digital record source (tick mark):
Computer / Storage Media DVR Mobile Flash Drive
CD/DVD Server Cloud Other
Other: ________________________________________
Make & Model: _______________ Color: _______________
Serial Number: _______________
IMEI/UIN/UID/MAC/Cloud ID_____________________ (as applicable)
and any other relevant information, if any, about the device/digital record_______(specify).
I state that the HASH value/s of the electronic/digital record/s is _____________________,
obtained through the following algorithm:
SHA1:
SHA256:
MD5:
Other__________________ (Legally acceptable standard)
(Hash report to be enclosed with the certificate)
(Name, designation and signature)
Date(DD/MM/YYYY): _____
Time (IST): ________hours (In 24 hours format)
Place: ____________

DIWAKAR SINGH,
Joint Secretary & Legislative Counsel to the Govt. of India.
MGIPMRND-533GI(S3)-25-12-2023. UPLOADED BY THE MANAGER, GOVERNMENT OF INDIA PRESS,
MINTO ROAD, NEW DELHI-110002 AND PUBLISHED BY THE CONTROLLER OF PUBLICATIONS,
DELHI-110054."""

REPORT_CSS = """
<style>
    body { font-family: Georgia, 'Times New Roman', serif; margin: 40px; color: #1a1a1a; }
    h1 { border-bottom: 3px solid #1a3d7c; padding-bottom: 8px; }
    h2 { color: #1a3d7c; margin-top: 32px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
    .meta { color: #555; font-size: 13px; }
    .schedule { font-family: 'Courier New', monospace; font-size: 11px; line-height: 1.4;
                white-space: pre-wrap; background: #fafafa; border: 1px solid #ccc;
                padding: 16px; page-break-before: always; }
    .item { padding: 4px 0; border-bottom: 1px solid #eee; }
</style>
"""


def generate_report(report_path, evidence, custody_records):
    """Build the evidence report and append the Schedule certificate verbatim."""

    evidence_html = "".join(
        f'<div class="item">{html.escape(str(item))}</div>' for item in evidence
    ) or '<div class="item">No evidence recorded.</div>'

    custody_html = "".join(
        f'<div class="item">{html.escape(str(record))}</div>' for record in custody_records
    ) or '<div class="item">No custody records.</div>'

    html_report = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Digital Forensic Evidence Report</title>
{REPORT_CSS}
</head>
<body>
<h1>Digital Forensic Evidence Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Evidence Details</h2>
{evidence_html}

<h2>Chain of Custody</h2>
{custody_html}

<div class="schedule">{html.escape(SCHEDULE_PAGE_1)}</div>
<div class="schedule">{html.escape(SCHEDULE_PAGE_2)}</div>

</body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_report)

    return report_path