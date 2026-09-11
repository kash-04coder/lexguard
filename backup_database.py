import sqlite3

conn = sqlite3.connect("forensic.db")

with open("forensic_backup.sql", "w", encoding="utf-8") as f:
    for line in conn.iterdump():
        f.write(f"{line}\n")
conn.close()
print("Database exported successfully!")
conn = sqlite3.connect("forensic.db")
cursor = conn.execute("""
SELECT sql
FROM sqlite_master
WHERE type='table';
""")

for row in cursor:
    print(row[0])
    print()