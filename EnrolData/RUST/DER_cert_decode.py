from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate

def extract_cert_from_der(der_hex_string):
    # Convert the hexadecimal string to binary (DER format)
    der_bytes = bytes.fromhex(der_hex_string)

    # Load the certificate from the DER-encoded bytes
    certificate = load_der_x509_certificate(der_bytes, default_backend())

    # Extract and return the certificate's public key
    public_key = certificate.public_key()

    # Serialize the public key to PEM format (optional)
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Return the PEM formatted public key and other certificate details
    return {
        "certificate": certificate,
        "public_key_pem": pem_public_key.decode("utf-8"),
        "subject": certificate.subject,
        "issuer": certificate.issuer,
        "serial_number": certificate.serial_number,
        "not_valid_before": certificate.not_valid_before,
        "not_valid_after": certificate.not_valid_after
    }

# Example usage:
der_hex_string = "3082035A30820242A00302010202141AC2E40167F2124788202A8617D5D3E6D8E6B71F300D06092A864886F70D01010B050030673120301E06035504030C1770726F6A6563747340617468616B7368616E612E636F6D310B300906035504061302534C3110300E06035504080C075765737465726E3110300E06035504070C07436F6C6F6D626F31123010060355040A0C095468616B7368616E61301E170D3234313130383130313631325A170D3235313130353130313631325A30673120301E06035504030C1770726F6A6563747340617468616B7368616E612E636F6D310B300906035504061302534C3110300E06035504080C075765737465726E3110300E06035504070C07436F6C6F6D626F31123010060355040A0C095468616B7368616E6130820122300D06092A864886F70D01010105000382010F003082010A0282010100A2A4EF812B29A5A79C0481078CA58ED63218091165241380FA5DB1E925CC4DDFAE599EBBB91CA1B9DE67C8A5795092B00B55264E960DE1FF2DD050CBEC2A2C00EC3430CFCB20BDEF05561285C413C2C6529DC24FD5F42B72FC0B1FAA91DC7FABCBA749D3A0C7A7AB36CF5D007583A4F80D10FCE60CBA1F97CCF04AD98037322B86D9EF872B2B1E7D5EA0DCA97F563577D630F030210286473AB7C898D02E88916ABAC5AECA39B339784B63A06FC9CD343E2C08EB1C15A50E584802615AB6C941C9226E8E7DF1E24F15D13C4E9232249044782BFB73B08E29C0CC89B613DBF15A924379714252F62B8E05A6372469A725F8A9CC91BA181C46E9ABF4DB7587F5E30203010001300D06092A864886F70D01010B050003820101009F94D5B8D0DE899CD907B96860B1E18D51082BAB2C4840186E0C5AFC26E6EA2E0AC3DB980E0E303DC7989D77D1F67C1C6BA89FBFC37BA120D3390F8B868F8CA04C1B0DD2751FD913320C2C931AECCBCD30FCAA135B5475AB6FF1CF463807C0A9D4A7CC857D2305A5559F6318977AF2EEB8093C5D946D96831ECB0A3E748E83A8F4770165F3EC9AE1E9CE97B4F168DA92364F3C792386D1EBBC8E1F509F90AF33BC7B1616893E011D175A0F7F659E0D993B2DCBA803A5773D3379D9D4BF307510D1F86EB6DF9F07E57C5B095B905C50C932C15D4CE77B2B8CB219540C5FC9F03031C5DE73751C975DFC9F0AA4B28B5D9398301C41D8B0D96BAF4AE1CE0B579E68"
result = extract_cert_from_der(der_hex_string)

# Print results
print("Public Key (PEM Format):")
print(result["public_key_pem"])

print("\nCertificate Details:")
print(f"Subject: {result['subject']}")
print(f"Issuer: {result['issuer']}")
print(f"Serial Number: {result['serial_number']}")
print(f"Valid From: {result['not_valid_before']}")
print(f"Valid Until: {result['not_valid_after']}")