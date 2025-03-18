import json

# Absolute path to the JSON file
file_path = 'student.json'

# Open and read the JSON file
with open(file_path, 'r') as file:
    data = json.load(file)

# Print the data
print(data)
