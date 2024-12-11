import json
from datetime import datetime, timezone
from typing import Tuple

# Constants for JSON keys
REQUEST_KEY = "Request"
DEVICE_TYPE_KEY = "DeviceType"
RESPONSE_KEY = "Response"
DEVICE_UUID_KEY = "DeviceUUID"
DEVICE_UUID_CERTIFICATE_KEY = "DeviceUUIDCertificate"
DEVICE_CERTIFICATE_PRIVATE_KEY_KEY = "DeviceCertificatePrivateKey"
DEVICE_CERTIFICATE_KEY = "DeviceCertificate"
DEVICE_KEY_KEY = "DeviceKey"
KMS_CERTIFICATE_KEY = "KMSCertificate"
TIMESTAMP_KEY = "TimeStamp"

def read_request(file_path: str) -> Tuple[str, str]:
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)

        request = data.get(REQUEST_KEY)
        device_type = data.get(DEVICE_TYPE_KEY)
        
        return request, device_type

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None, None
    except json.JSONDecodeError:
        print(f"Error: The file {file_path} is not a valid JSON.")
        return None, None


def get_timestamp() -> str:
    # Get the current UTC time
    now = datetime.now(timezone.utc)
    
    # Format the timestamp with only 4 digits for microseconds
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:04d}"
    
    return timestamp


def write_response(
    response: str,
    device_type: str,
    device_uuid: str,
    device_uuid_certificate: str,
    device_certificate_private_key: str,
    device_certificate: str,
    device_key: str,
    kms_certificate: str,
    file_path: str
) -> None:
    # Create a dictionary to represent the JSON object
    json_data = {
        RESPONSE_KEY: response,
        DEVICE_TYPE_KEY: device_type,
        DEVICE_UUID_KEY: device_uuid,
        DEVICE_UUID_CERTIFICATE_KEY: device_uuid_certificate,
        DEVICE_CERTIFICATE_PRIVATE_KEY_KEY: device_certificate_private_key,
        DEVICE_CERTIFICATE_KEY: device_certificate,
        DEVICE_KEY_KEY: device_key,
        KMS_CERTIFICATE_KEY: kms_certificate,
        TIMESTAMP_KEY: get_timestamp()
    }
    
    try:
        # Write the dictionary to a JSON file
        with open(file_path, 'w') as file:
            json.dump(json_data, file, indent=4)  # `indent=4` makes the output more readable
        print(f"Response written to {file_path} successfully.")

    except IOError as e:
        print(f"Error writing to file {file_path}: {e}")
