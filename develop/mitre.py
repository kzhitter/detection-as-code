import requests
import tomllib
import os
import sys

url= "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
headers={
    "Accept": "application/json"
    }

mitreData = requests.get(url, headers=headers).json()
mitreMapped = {}
failure=0
# def getMapping():
for objects in mitreData['objects']:
    tactics = []
    if objects['type'] == 'attack-pattern':
        if 'external_references' in objects:
            for reference in objects['external_references']:
                if 'external_id' in reference:
                    if((reference['external_id'].startswith("T"))):
                        if'kill_chain_phases' in objects:
                            for tactic in(objects['kill_chain_phases']):
                                tactics.append(tactic)
                        technique = reference['external_id']
                        name = objects['name']
                        url = reference['url']
                        
                        if 'x_mitre_platforms' in objects:
                            deprecated = objects['x_mitre_deprecated']
                            filtered_objects = {'tactics':tactics, 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                            mitreMapped[technique] = filtered_objects
                        else:
                            filtered_objects = {'tactics':tactics, 'technique': technique, 'name': name, 'url': url, 'deprecated': "False"}
                            mitreMapped[technique] = filtered_objects


alert_data = {}                         
for root,dirs,files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert=tomllib.load(toml)
                filtered_objects_array=[]
                
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert ['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']
                        
                        #print(f"file: {file} - technique_id: {technique_id} - technique_name: {technique_name}")
                        
                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic = "N/A"
                        
                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "N/A"
                            subtechnique_name = "N/A"
                            
                        filtered_objects = {  'tactic': tactic, 'technique_id': technique_id, 'technique_name': technique_name, 'subtechnique_id': subtechnique_id, 'subtechnique_name': subtechnique_name}
                        filtered_objects_array.append(filtered_objects)
                        alert_data[file] = filtered_objects_array
                        
                
                
mitre_tactic_list = ["none","reconnaissance", "resource development", "initial access", "execution", "persistence", "privilege escalation", "defense evasion", "credential access", "discovery", "lateral movement", "collection", "command and control", "exfiltration", "impact"]
                
for file in alert_data:
    for line in alert_data[file]:
        tactic=line['tactic'].lower()
        technique_id=line['technique_id']
        subtechnique_id=line['subtechnique_id']
        
        # check to ensure MITRE Tactics exist
        if tactic not in mitre_tactic_list:
            print(f"The MITRE Tactic is not valid - file: {file} - tactic: {tactic}")
            failure = 1
        
        # check to make sure the MITRE Technique Id is valid
        try:
            if mitreMapped[technique_id]:
                pass
        except KeyError:
            print(f"The MITRE Technique Id is not valid - file: {file} - technique_id: {technique_id}")
            failure = 1
            
        # check to see if the MITRE TID + name combination is valid
        try:
            mitre_name= mitreMapped[technique_id]['name']
            alert_name= line['technique_name']
            if mitre_name != alert_name:
                print(f"MITRE Technique ID and name mismatch - file: {file} -  expected Name: {mitre_name} - given Name: {alert_name}")
                failure = 1
        except KeyError:
            pass
        
        
        # check to see if the subTID + name combination is valid
        try:
            if subtechnique_id != "N/A":
                mitre_subtechnique_name= mitreMapped[subtechnique_id]['name']
                alert_subtechnique_name= line['subtechnique_name']
                if mitre_subtechnique_name != alert_subtechnique_name:
                    print(f"MITRE Sub-Technique ID and name mismatch - file: {file} -  expected Name: {mitre_subtechnique_name} - given Name: {alert_subtechnique_name}")
                    failure = 1
        except KeyError:
            pass
        
        # check to see if the technique is deprecated
        try:
            if mitreMapped[technique_id]['deprecated'] == True:
                print(f"MITRE Technique is deprecated - file: {file} - technique_id: {technique_id}")
                failure = 1
        except KeyError:
            pass

if failure !=0:
    sys.exit(1)