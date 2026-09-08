import tomllib
import sys
import os

#file="alert_example.toml"
#with open(file, "rb") as toml:
#               alert=tomllib.load(toml)
failure=0

for root,dirs,files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert=tomllib.load(toml)
                
                present_fields = []
                missing_fields = []
                
                try:
                    if alert['metadata']['creation_date']:
                       pass 
                except:
                    print("The metadata table does not contain a creation_date on: " + full_path)
                    failure = 1

                if alert['rule']['type'] == "query":
                    required_fields = ["name", "description", "type", "query", "severity", "risk_score", "rule_id"]
                elif alert['rule']['type'] == "eql": # event correlation alert
                    required_fields = ["name", "description", "type", "query", "severity", "risk_score", "language", "rule_id"]
                elif alert['rule']['type'] == "threshold": # threshold alert
                    required_fields = ["name", "description", "type", "severity", "risk_score", "threshold", "rule_id"]
                else:
                    print(f"Unsupported rule type found in - full_path: {full_path} - type: {alert['rule']['type']}")
                    break

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)


                if missing_fields:
                    print(f"Missing required fields in file - {file}: {missing_fields}")
                    failure = 1
                else:
                    print(f"validation passed! - All required fields are present in file - {file}")
                    
if failure !=0:
    sys.exit(1)
