import glob
import os
import re
import shutil

DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.json$")
MONTHS = ["January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December"]


def migrate():
    moved = 0
    for path in glob.glob("vulnerabilities/data/*.json"):
        fname = os.path.basename(path)
        m = DATE_RE.match(fname)
        if not m:
            continue
        year, month_num, _ = m.groups()
        month_name = MONTHS[int(month_num) - 1]
        new_dir = f"vulnerabilities/data/{year}/{month_name}"
        os.makedirs(new_dir, exist_ok=True)
        new_path = f"{new_dir}/{fname}"
        shutil.move(path, new_path)
        moved += 1
        print(f"Moved {path} -> {new_path}")

    removed = 0
    for path in glob.glob("vulnerabilities/*.md"):
        fname = os.path.basename(path)
        if DATE_RE.match(fname.replace(".md", ".json")):
            os.remove(path)
            removed += 1
            print(f"Removed stale flat file {path}")

    print(f"\nDone. Moved {moved} JSON file(s), removed {removed} old flat .md file(s).")
    print("Run the main script next — it will regenerate everything under vulnerabilities/<year>/<month>/.")


if __name__ == "__main__":
    migrate()
