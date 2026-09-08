import requests
import os
import tomllib


url = "https://my-security-project-cc30e1.kb.ap-southeast-1.aws.elastic.cloud/api/detection_engine/rules"
api_key=os.environ('ELASTIC_API_KEY')
headers={
   'Authorization': f'ApiKey {api_key}',
   'Content-Type': 'application/json',
   'kbn-xsrf': 'true'
   
}

changed_files=os.environ["CHANGED_FILES"]

for root,dirs,files in os.walk("detections/"):
    for file in files:
        if file in changed_files:
            # if "bat_files_observed_in_http_traffic_on_unusual_port.toml" in "detections/network/bat_files_observed_in_http_traffic_on_unusual_port.toml"
            data ="{\n"
            if file.endswith(".toml"):
                full_path = os.path.join(root, file)
                with open(full_path, "rb") as toml:
                    alert=tomllib.load(toml)
                    
                    if alert['rule']['type'] == "query":
                        required_fields = ["author", "name", "description", "type", "query", "severity", "risk_score", "threat", "rule_id"]
                    elif alert['rule']['type'] == "eql": # event correlation alert
                        required_fields = ["author", "name", "description", "type", "query", "severity", "risk_score", "language", "threat", "rule_id"]
                    elif alert['rule']['type'] == "threshold": # threshold alert
                        required_fields = ["author", "name", "description", "type", "severity", "risk_score", "threshold", "threat", "rule_id"]
                    else:
                        print(f"Unsupported rule type found in - full_path: {full_path} - type: {alert['rule']['type']}")
                        break
                    
                    
                    for field in alert['rule']:
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                            
                        elif type(alert['rule'][field]) == str:
                            if field == 'description':
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"").replace("\\","\\\\") + "\"," + "\n"
                            elif field == 'query':
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"","\\\"").replace("\n"," ") + "\"," + "\n"
                            else:
                                data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"") + "\"," + "\n"
                        
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                        
                        elif type(alert['rule'][field]) == dict:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                    data += "  \"enabled\": true\n}"
                    
                    rule_id = alert['rule']['rule_id']
                    
                    url= url + "?rule_id=" + rule_id
                    
                    elastic_data= requests.put(url, headers=headers, data=data).json()
                    print(elastic_data)