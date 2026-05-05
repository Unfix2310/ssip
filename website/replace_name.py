import os
import glob

workspace = "/Volumes/Code/SSIP/website"
files = glob.glob(f"{workspace}/**/*.html", recursive=True) + glob.glob(f"{workspace}/**/*.js", recursive=True) + glob.glob(f"{workspace}/**/*.json", recursive=True)

for f in files:
    if "node_modules" in f:
        continue
    with open(f, "r") as file:
        content = file.read()
        
    if "ReguLex" in content or "regulex" in content:
        new_content = content.replace("ReguLex", "Ansark").replace("regulex", "ansark")
        with open(f, "w") as file:
            file.write(new_content)
            print(f"Updated {f}")
