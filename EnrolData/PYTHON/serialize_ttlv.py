import struct

def serialize_ttlv(tag, value_type, value):
    # Define tag (e.g., 2 bytes), value_type (e.g., 1 byte), length (e.g., 2 bytes)
    ttlv_data = b''
    
    # Tag: let's assume we use short numeric tags
    tag_bytes = struct.pack(">H", tag)  # 2 bytes for tag

    # Type: let's assume we use one byte to indicate type (0x01: string, 0x02: integer, etc.)
    type_bytes = struct.pack("B", value_type)  # 1 byte for type
    
    # Value and Length: we calculate the length of the value and store it in 2 bytes
    if value_type == 0x01:  # String type
        value_bytes = value.encode('utf-8')
    elif value_type == 0x02:  # Integer type
        value_bytes = struct.pack(">I", value)  # 4-byte integer
    elif value_type == 0x03:  # Boolean type
        value_bytes = struct.pack("?", value)  # 1-byte boolean
    else:
        value_bytes = b''

    length_bytes = struct.pack(">H", len(value_bytes))  # 2 bytes for length

    # Append tag, type, length, and value together
    ttlv_data += tag_bytes + type_bytes + length_bytes + value_bytes
    return ttlv_data

# Example conversion of the people list
def convert_people_to_ttlv(people):
    ttlv_result = b''
    
    # Tag definitions (arbitrary example)
    TAG_NAME = 1
    TAG_AGE = 2
    TAG_CITY = 3
    TAG_IS_STUDENT = 4
    TAG_SKILLS = 5

    for person in people:
        ttlv_result += serialize_ttlv(TAG_NAME, 0x01, person["name"])           # Name as string
        ttlv_result += serialize_ttlv(TAG_AGE, 0x02, person["age"])             # Age as integer
        ttlv_result += serialize_ttlv(TAG_CITY, 0x01, person["city"])           # City as string
        ttlv_result += serialize_ttlv(TAG_IS_STUDENT, 0x03, person["is_student"])  # Boolean
        
        # For skills (array of strings), you may need to create a loop
        for skill in person["skills"]:
            ttlv_result += serialize_ttlv(TAG_SKILLS, 0x01, skill)  # Each skill as a string

    return ttlv_result

def decode_ttlv(ttlv_data):
    index = 0
    while index < len(ttlv_data):
        # Read Tag (2 bytes)
        tag = struct.unpack(">H", ttlv_data[index:index+2])[0]
        index += 2

        # Read Type (1 byte)
        value_type = struct.unpack("B", ttlv_data[index:index+1])[0]
        index += 1

        # Read Length (2 bytes)
        length = struct.unpack(">H", ttlv_data[index:index+3])[0]
        index += 2

        # Read Value (according to length)
        value = ttlv_data[index:index+length]
        index += length

        # Interpret the value based on the type
        if value_type == 0x01:  # String
            print(f"Tag {tag}: String - {value.decode('utf-8')}")
        elif value_type == 0x02:  # Integer
            print(f"Tag {tag}: Integer - {struct.unpack('>I', value)[0]}")
        elif value_type == 0x03:  # Boolean
            print(f"Tag {tag}: Boolean - {'True' if struct.unpack('?', value)[0] else 'False'}")
        else:
            print(f"Tag {tag}: Unknown type")
            
# Sample data
people = [
    {
        "name": "Alice",
        "age": 25,
        "city": "New York",
        "is_student": False,
        "skills": ["Python", "Data Analysis", "Machine Learning"]
    },
    {
        "name": "Bob",
        "age": 30,
        "city": "San Francisco",
        "is_student": True,
        "skills": ["JavaScript", "React", "Node.js"]
    }
]

# Convert people data to TTLV format
ttlv_data = convert_people_to_ttlv(people)
# print(ttlv_data)

print(decode_ttlv(ttlv_data))
