#include "crow.h"              // Include Crow (assuming it's in the include path)
#include "libcurl/curl/curl.h" // Include libcurl for HTTP requests
#include <iostream>
#include <string>

// Function to capture response from libcurl
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// Function to send POST request using libcurl
std::string sendPostRequest(const std::string &url, const std::string &jsonPayload)
{
    CURL *curl;
    CURLcode res;
    std::string response;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl)
    {
        // Set URL for the request
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Set headers to indicate JSON content type
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());

        // Capture response data in a string
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Perform the request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        // Cleanup
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();
    return response;
}

int main()
{
    crow::SimpleApp app;

    // Define an endpoint to trigger the KMIP request
    CROW_ROUTE(app, "/trigger_kmip")
    ([]()
     {
        // JSON payload for the KMIP request
        std::string jsonPayload = R"({
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

        // URL for the KMIP server endpoint
        std::string url = "http://localhost:9998/kmip/2_1";

        // Send the POST request
        std::string response = sendPostRequest(url, jsonPayload);

        // Return the response received from the KMIP server
        return crow::response(response); });

    // Start the server on port 8080
    app.port(8080).multithreaded().run();

    return 0;
}
