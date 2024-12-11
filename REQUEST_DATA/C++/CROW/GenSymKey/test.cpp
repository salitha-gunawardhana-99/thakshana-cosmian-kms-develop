#include <iostream>
#include <string>
#include "libcurl/curl/curl.h"

size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp)
{
    size_t totalSize = size * nmemb;
    userp->append((char *)contents, totalSize);
    return totalSize;
}

int main()
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    // Initialize curl
    curl = curl_easy_init();
    if (curl)
    {
        // Set the URL for the request
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:9998/kmip/2_1");

        // Specify that we are sending a JSON request
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // JSON body to send
        const char *jsonData = R"({
            "tag": "Create",
            "type": "Structure",
            "value": [
                {
                    "tag": "ObjectType",
                    "type": "Enumeration",
                    "value": "SymmetricKey"
                },
                {
                    "tag": "Attributes",
                    "type": "Structure",
                    "value": [
                        {
                            "tag": "CryptographicAlgorithm",
                            "type": "Enumeration",
                            "value": "AES"
                        },
                        {
                            "tag": "CryptographicLength",
                            "type": "Integer",
                            "value": 256
                        },
                        {
                            "tag": "CryptographicUsageMask",
                            "type": "Integer",
                            "value": 2108
                        },
                        {
                            "tag": "KeyFormatType",
                            "type": "Enumeration",
                            "value": "TransparentSymmetricKey"
                        },
                        {
                            "tag": "ObjectType",
                            "type": "Enumeration",
                            "value": "SymmetricKey"
                        },
                        {
                            "tag": "VendorAttributes",
                            "type": "Structure",
                            "value": [
                                {
                                    "tag": "VendorAttributes",
                                    "type": "Structure",
                                    "value": [
                                        {
                                            "tag": "VendorIdentification",
                                            "type": "TextString",
                                            "value": "cosmian"
                                        },
                                        {
                                            "tag": "AttributeName",
                                            "type": "TextString",
                                            "value": "tag"
                                        },
                                        {
                                            "tag": "AttributeValue",
                                            "type": "ByteString",
                                            "value": "5B226D794B6579225D"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        })";

        // Set the JSON data to send
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData);

        // Set the callback function to handle the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Perform the request, res will get the return code
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK)
        {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        else
        {
            // Print the response
            std::cout << "Response: " << readBuffer << std::endl;
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return 0;
}
