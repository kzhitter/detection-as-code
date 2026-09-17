import tomllib
import os
import datetime
from calendar import monthrange

current = {}
one_month = {}
two_months = {}

filtered_object_array = []


def month_key(value):
    return f"{value.year}-{value.month:02d}"


def shift_months(date_value, months):
    month_index = date_value.year * 12 + (date_value.month - 1) + months
    year = month_index // 12
    month = (month_index % 12) + 1
    day = min(date_value.day, monthrange(year, month)[1])
    return date_value.replace(year=year, month=month, day=day)


today = datetime.date.today()
current_month = month_key(today)
one_month_ago = month_key(shift_months(today, -1))
two_month_ago = month_key(shift_months(today, -2))

for root, dirs, files in os.walk("detections/"):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                metadata = alert.get('metadata', {})
                date = metadata.get('creation_date')
                if not date:
                    print(f"Skipping {full_path}: missing metadata.creation_date")
                    continue
                name = alert['rule']['name']
                author = alert['rule']['author']
                risk_score = alert['rule']['risk_score']
                severity = alert['rule']['severity']
                filtered_object_array = []

                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for x in alert['rule']['threat']:
                        technique_id = x['technique'][0]['id']
                        technique_name = x['technique'][0]['name']
  
                        if 'tactic' in x:
                            tactic = x['tactic']['name']
                        else:
                            tactic = "none"
                        
                        if 'subtechnique' in x['technique'][0]:
                            subtechnique_id = x['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = x['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"

                        technique = technique_id + " - " + technique_name
                        subtech = subtechnique_id + " - " + subtechnique_name

                        obj = {'tactic': tactic, 'technique': technique, 'subtech': subtech, 'subtech': subtech}
                        filtered_object_array.append(obj)
                
                obj = {'name': name, 'date': date, 'author': author, 'risk_score': risk_score, 'severity': severity, 'mitre': filtered_object_array}
                
                year = date.replace("/","-").split("-")[0]
                month = date.replace("/","-").split("-")[1]
                date_compare = year + "-" + month
                if date_compare == current_month:
                    current[file] = obj
                elif date_compare == one_month_ago:
                    one_month[file] = obj
                elif date_compare == two_month_ago:
                    two_months[file] = obj

output_path = "metrics/latestdetections.md"
separator = "; "

os.makedirs(os.path.dirname(output_path), exist_ok=True)
outF = open(output_path, "w")
outF.write("# Detection Report\n")

# Current Month
outF.write("## Current Month\n")
outF.write("### New Alerts\n\n")
outF.write("| Alert | Date | Author | Risk Score | Severity |\n")
outF.write("| --- | --- | --- | --- | --- |\n")
for line in current.values():
    tactic = []
    tech = []
    subtechnique = []

    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",".")
    risk_score = str(line['risk_score'])
    severity = line['severity']
    
    for technique in line['mitre']:
        tactic.append(technique['tactic'])
        tech.append(technique['technique'])
        subtechnique.append(technique['subtech'])
    outF.write("|" + name + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|\n")

# Two Months Ago
outF.write("## Last Month\n")
outF.write("### Alerts\n\n")
outF.write("| Alert | Date | Author | Risk Score | Severity |\n")
outF.write("| --- | --- | --- | --- | --- |\n")
for line in one_month.values():
    tactic = []
    tech = []
    subtechnique = []

    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",".")
    risk_score = str(line['risk_score'])
    severity = line['severity']
    
    for technique in line['mitre']:
        tactic.append(technique['tactic'])
        tech.append(technique['technique'])
        subtechnique.append(technique['subtech'])
    outF.write("|" + name + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|\n")

# Two Months Ago
outF.write("## Two Months Ago\n")
outF.write("### Alerts\n\n")
outF.write("| Alert | Date | Author | Risk Score | Severity |\n")
outF.write("| --- | --- | --- | --- | --- |\n")
for line in two_months.values():
    tactic = []
    tech = []
    subtechnique = []

    date = line['date']
    name = line['name']
    author = str(line['author']).replace(",",".")
    risk_score = str(line['risk_score'])
    severity = line['severity']
    
    for technique in line['mitre']:
        tactic.append(technique['tactic'])
        tech.append(technique['technique'])
        subtechnique.append(technique['subtech'])
    outF.write("|" + name + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|\n")

outF.close()