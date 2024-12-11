import handle_json

request, device_type = handle_json.read_request("JSONfiles/RequestEnrolData.json")

print(request, device_type)