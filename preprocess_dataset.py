import json

# Load the MITRE ATT&CK dataset
with open("enterprise-attack.json", "r",encoding="utf-8") as f:
    attack_data = json.load(f)

# Create a dictionary for faster lookups
technique_db = {}
for technique in attack_data["objects"]:
    if technique.get("type") == "attack-pattern" and technique.get("external_references"):
        for ref in technique["external_references"]:
            if ref.get("external_id"):
                technique_db[ref["external_id"]] = {
                    "name": technique.get("name", "Unknown"),
                    "description": technique.get("description", "No description available."),
                }

# Save the preprocessed dataset
with open("technique_db.json", "w") as f:
    json.dump(technique_db, f)

print("Dataset preprocessed and saved as 'technique_db.json'.")