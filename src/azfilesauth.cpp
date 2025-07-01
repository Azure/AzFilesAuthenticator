#include <stdexcept>
#include <curl/curl.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <ctime>
#include <krb5.h>
#include <fstream>
#include <vector>
#include <sstream>
#include "azfilesauth.h"
#include <unistd.h>
#include <syslog.h>

int smb_clear_credential(const std::string& file_endpoint_uri, uid_t user_uid);

// Check if a file exists
bool fileExists(const std::string& filename) {
    return access(filename.c_str(), F_OK) == 0;
}

// Read config yaml file
std::string read_config_value(const std::string& key) {
    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    std::ifstream file(CONFIG_FILE_PATH);
    if (!file.is_open()) {
        syslog(LOG_ERR, "Cannot open config file %s", CONFIG_FILE_PATH);
        return "";
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t colon_pos = line.find(":");
        if (colon_pos != std::string::npos) {
            std::string found_key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);

            // Trim whitespace
            found_key.erase(0, found_key.find_first_not_of(" \t"));
            found_key.erase(found_key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t\""));
            value.erase(value.find_last_not_of(" \t\"") + 1);

            if (found_key == key) {
                closelog();
                return value;
            }
        }
    }
    
    closelog();
    return ""; // Key not found
}

std::string parse_principal_into_string(const krb5_principal principal) {
    std::string principal_str;
    for (int i = 0; i < principal->length; i++) {
        if (i > 0) {
            principal_str += "/";
        }
        principal_str += std::string(principal->data[i].data, principal->data[i].length);
    }
    principal_str += "@";
    principal_str += std::string(principal->realm.data, principal->realm.length);
    return principal_str;
}

// Parses the value associated with a given key from a JSON-formatted string.
std::string parseValue(const std::string& json, const std::string& key) {
    std::string keyWithQuotes = "\"" + key + "\":\"";
    size_t startPos = json.find(keyWithQuotes);
    if (startPos == std::string::npos) {
        return ""; // Key not found
    }
    startPos += keyWithQuotes.length();
    size_t endPos = json.find("\"", startPos);
    if (endPos == std::string::npos) {
        return ""; // Closing quote not found
    }
    return json.substr(startPos, endPos - startPos);
}

// Checks if a character is a valid Base64 character.
bool isBase64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

// Decodes a Base64-encoded string.
std::pair<std::string, size_t> decodeBase64(const std::string& encoded) {
    const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string decoded;
    size_t in_len = encoded.size();
    size_t i = 0;
    size_t in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded[in_] != '=') && isBase64(encoded[in_])) {
        char_array_4[i++] = encoded[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (size_t j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (size_t j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (size_t j = 0; j < i - 1; j++)
            decoded += char_array_3[j];
    }

    return {decoded, decoded.size()};
}

// Callback to capture response body
size_t write_body_callback(void *contents, size_t size, size_t nmemb, std::string *response) {
    size_t total_size = size * nmemb;
    response->append((char *)contents, total_size);
    return total_size;
}

// Callback to capture response headers
size_t write_header_callback(char *buffer, size_t size, size_t nitems, std::string *headers) {
    size_t total_size = size * nitems;
    headers->append(buffer, total_size);
    return total_size;
}

// Helper function to read timeout value from config or use default
long get_timeout_from_config(const std::string& key, long default_value) {
    std::string value_str = read_config_value(key);
    if (!value_str.empty()) {
        char* endptr = nullptr;
        long val = strtol(value_str.c_str(), &endptr, 10);
        if (endptr != value_str.c_str() && val > 0) {
            return val;
        }
    }
    return default_value;
}

// Retrieves a Kerberos service ticket from a specified resource URI using an OAuth token.
int get_kerberos_service_ticket(const std::string& resource_uri,
                        const std::string& oauth_token,
                        std::string& expiration,
                        std::string& session_key,
                        std::string& krb_service_ticket) 
{
    std::string request_url;
    CURL* curl;
    CURLcode curl_rc;
    struct curl_slist* headers = NULL;
    std::string auth_header;
    std::string x_ms_date_header;
    std::string res_headers;
    std::string res_body;
    time_t rawtime;
    struct tm timeinfo;
    long http_res_code;
    char buffer[128];

    expiration = "";
    session_key = "";
    krb_service_ticket = "";

    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    // check if resource_uri is prefixed properly
    if ((resource_uri.substr(0, 7) != "http://") && 
        (resource_uri.substr(0, 8) != "https://")) {
        syslog(LOG_ERR, "resource_uri is not prefixed with 'http://' or 'https://'. resource_uri provided: %s", resource_uri.c_str());
        goto inval_out;
    }

    // check if resource_uri previx is https://
    if (resource_uri.substr(0, 7) == "http://") {
        syslog(LOG_ERR, "resource_uri is not prefixed with 'https://'. resource_uri provided: %s", resource_uri.c_str());
        goto inval_out;
    }

    // make full URL
    request_url = resource_uri + "?restype=service&comp=kerbticket";

    // init curl global components
    curl_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_global_init() failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // create curl handle
    curl = curl_easy_init();
    if (!curl) {
        syslog(LOG_ERR, "curl_easy_init() failed");
        goto out_curl;
    }

    // set URL
    curl_rc = curl_easy_setopt(curl, CURLOPT_URL, request_url.c_str());
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_URL) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // Set timeouts
    curl_rc = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, get_timeout_from_config("CURL_CONNECT_TIMEOUT", 10L));
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_CONNECTTIMEOUT) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }
    curl_rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, get_timeout_from_config("CURL_TOTAL_TIMEOUT", 30L));
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_TIMEOUT) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // enable verbose mode
    curl_rc = curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    // replicate windows api behavior, setting various fields accordingly:
    // Setting user agent to AzureFilesSmbAuth
    curl_rc = curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT); 
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_USERAGENT) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // Setting as a POST req, a long value is expected
    curl_rc = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_POST) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    auth_header = AUTHORIZATION_HEADER + oauth_token;           // "Authorization: Bearer " + oauth_token

    headers = curl_slist_append(headers, ACCEPT_TYPES);         // Accept: */*, same as WINHTTP_DEFAULT_ACCEPT_TYPES
    headers = curl_slist_append(headers, API_VERSION);          // Setting API version
    headers = curl_slist_append(headers, auth_header.c_str());  // Setting authorization header

    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    
    // Get current time
    std::time(&rawtime);

    // Convert to GMT
    gmtime_r(&rawtime, &timeinfo);

    // Format the date
    std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &timeinfo);

    x_ms_date_header = X_MS_DATE_HEADER + std::string(buffer);  // "x-ms-date: " + buffer

    headers = curl_slist_append(headers, x_ms_date_header.c_str()); // Setting x-ms-date header

    // Setting headers
    curl_rc = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_HTTPHEADER) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // Capture response body
    curl_rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body_callback);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_WRITEFUNCTION) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // Set response body to res_body
    curl_rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res_body);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_WRITEDATA) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // Capture response headers
    curl_rc = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_callback);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_HEADERFUNCTION) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // Set response headers to res_headers
    curl_rc = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &res_headers);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "curl_easy_setopt(CURLOPT_HEADERDATA) failed: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // send the request
    curl_rc = curl_easy_perform(curl);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "Failed to send HTTPS request: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // get response code
    curl_rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_res_code);
    if (curl_rc != CURLE_OK) {
        syslog(LOG_ERR, "Failed to get response code: %s", curl_easy_strerror(curl_rc));
        goto out_curl;
    }

    // mostly for debugging
    syslog(LOG_INFO, "HTTP response code: %ld", http_res_code);

    // check if response code is 200
    if (http_res_code != 200) {
        syslog(LOG_ERR, "Request failed: %ld", http_res_code);
        syslog(LOG_ERR, "Response headers: %s", res_headers.c_str());
        syslog(LOG_ERR, "Response body: %s", res_body.c_str());
        goto out_curl;
    }

    expiration          = parseValue(res_body, "expirationTime");
    session_key         = parseValue(res_body, "sessionKey");
    krb_service_ticket  = parseValue(res_body, "kerberosServiceTicket");

    curl_slist_free_all(headers);
    curl_global_cleanup();
    
    return 0;

    inval_out:
        errno = EINVAL;
        return -1;

    out_curl:
    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    printf("Error getting Kerberos service ticket, check /var/log/syslog for more information.\n");
    return -1;
}


// Inserts a Kerberos credential into the credential cache.
int smb_insert_credential(const std::string& file_endpoint_uri, const char* krb_ticket_data,
		size_t krb_ticket_size, uid_t user_uid) {
    krb5_context context = NULL;
    krb5_error_code ret;
    krb5_auth_context auth_context = NULL;
    krb5_data encoded_krbcred;
    krb5_creds **decoded_cred = NULL, *creds;
    krb5_ccache cache;
    krb5_principal client, server, existing_principal;
    std::string krb5_cc_name_str;
    std::string krb5_cc_name_construct;
    const char* cache_name;
    const char* KRB5_CC_NAME;

    // Use read_config_value to get the value of KRB5_CC_NAME
    krb5_cc_name_str = read_config_value("KRB5_CC_NAME");

    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    if (krb5_cc_name_str.empty()) {
        syslog(LOG_INFO, "Failed to read KRB5_CC_NAME from config file at %s", CONFIG_FILE_PATH);
        syslog(LOG_INFO, "Defaulting to default ccache for azfilesuser with UID: %d", user_uid);
        krb5_cc_name_construct = "FILE:/tmp/krb5cc_" + std::to_string(user_uid);
    } else {
        krb5_cc_name_construct = krb5_cc_name_str;
    }
    KRB5_CC_NAME = krb5_cc_name_construct.c_str();
    
    // Initialize Kerberos context
    ret = krb5_init_context(&context);
    if (ret) {
        syslog(LOG_ERR, "Error initializing Kerberos context: %s", krb5_get_error_message(context, ret));
        goto out;
    }

    encoded_krbcred.data = (char *) krb_ticket_data;
    if (!encoded_krbcred.data) {
        syslog(LOG_ERR, "Error allocating memory to encoded_krbcred.data: %s", strerror(errno));
        goto out;
    }

    encoded_krbcred.length = krb_ticket_size;

    // Initialize an auth context
    ret = krb5_auth_con_init(context, &auth_context);
    if (ret) {
        syslog(LOG_ERR, "Error initializing auth context: %s", krb5_get_error_message(context, ret));
        goto out;
    }

    // Decode the KRB-CRED message
    ret = krb5_rd_cred(context, auth_context, &encoded_krbcred, &decoded_cred, NULL);
    if (ret) {
        syslog(LOG_ERR, "Error decoding KRB-CRED: %s", krb5_get_error_message(context, ret));
        goto out;
    }

    ret = krb5_cc_resolve(context, KRB5_CC_NAME, &cache);
    if (ret) {
        syslog(LOG_ERR, "Failed to resolve credential cache: %s", krb5_get_error_message(context, ret));
        goto out;
    }

    ret = krb5_cc_get_principal(context, cache, &existing_principal);
    if (ret == 0) {
        if (!krb5_principal_compare(context, existing_principal, decoded_cred[0]->client)) {
            syslog(LOG_ERR, "Credential cache already contains a different client principal: %s", existing_principal->data->data);
            krb5_free_principal(context, existing_principal);
            goto out;
        } else {
            syslog(LOG_INFO, "Credential cache contains the expected client principal: %s", existing_principal->data->data);
        }
        krb5_free_principal(context, existing_principal);
    } else if (ret == KRB5_FCC_NOFILE) {
        syslog(LOG_INFO, "No credential cache file found at %s", KRB5_CC_NAME);
        syslog(LOG_INFO, "Creating new credential cache file");
        // Initialize the credential cache with the client principal
        int ret2 = krb5_cc_initialize(context, cache, decoded_cred[0]->client);
        if (ret2) {
            syslog(LOG_ERR, "Failed to initialize credential cache: %s", krb5_get_error_message(context, ret));
            goto out;
        }
    } else {
        syslog(LOG_ERR, "Failed to get principal from credential cache: %s", krb5_get_error_message(context, ret));
        goto out;
    }

    // Print the current credential cache location
    cache_name = krb5_cc_get_name(context, cache);
    if (cache_name) {
        syslog(LOG_INFO, "Current credential cache location: %s", cache_name);
    } else {
        syslog(LOG_ERR, "Failed to get credential cache location");
        goto out;
    }

    //clear credentials from cache before inserting new one for same file uri
    smb_clear_credential(file_endpoint_uri, user_uid);
    // Process the decoded credentials
    for (int i = 0; decoded_cred[i] != NULL; i++) {
        syslog(LOG_INFO, "Ticket %d:", i);
        syslog(LOG_INFO, "  Server: %s", std::string(decoded_cred[i]->server->data->data, decoded_cred[i]->server->data->length).c_str());
        syslog(LOG_INFO, "  Client: %s", std::string(decoded_cred[i]->client->data->data, decoded_cred[i]->client->data->length).c_str());
        syslog(LOG_INFO, "  Realm: %s", std::string(decoded_cred[i]->server->realm.data, decoded_cred[i]->server->realm.length).c_str());
        syslog(LOG_INFO, "  Ticket flags: %d", decoded_cred[i]->ticket_flags);

        creds = decoded_cred[i];

        // Insert the ticket into the cache
        ret = krb5_cc_store_cred(context, cache, creds);
        if (ret) {
            syslog(LOG_ERR, "Failed to store credentials in cache: %s", krb5_get_error_message(context, ret));
            goto out;
        }

        syslog(LOG_INFO, "Successfully stored credentials in cache.");
    }

    krb5_auth_con_free(context, auth_context);
    for (int i = 0; decoded_cred[i] != NULL; i++) {
        krb5_free_cred_contents(context, decoded_cred[i]);
        krb5_free_creds(context, decoded_cred[i]);
    }

    free(decoded_cred);
    if (context) krb5_free_context(context);

    return 0;

    out:
    printf("Error inserting credential, check /var/log/syslog for more information.\n");
    if (auth_context) {
        krb5_auth_con_free(context, auth_context);
    }
    if (decoded_cred != NULL) {
        for (int i = 0; decoded_cred[i] != NULL; i++) {
            krb5_free_cred_contents(context, decoded_cred[i]);
            krb5_free_creds(context, decoded_cred[i]);
        }
        free(decoded_cred);
    }
    if (context) {
        krb5_free_context(context);
    }
    return 1;
}

int smb_set_credential_oauth_token(const std::string& file_endpoint_uri,
                        const std::string& oauth_token,
                        unsigned int* credential_expires_in_seconds,
                        uid_t user_uid) 
{
    std::string expiration;
    std::string session_key;
    std::string krb_ticket;
    std::pair<std::string, size_t> decoded_pair;
    std::string decoded;
    size_t size;
    int rc = 0;

    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    if (credential_expires_in_seconds) {
        *credential_expires_in_seconds = 0;
    }

    if (&file_endpoint_uri == nullptr || file_endpoint_uri.empty()) {
        syslog(LOG_ERR, "file_endpoint_uri is empty");
        goto out;
    }
    if (&oauth_token == nullptr || oauth_token.empty()) {
        syslog(LOG_ERR, "oauth_token is empty");
        goto out;
    }
    if (credential_expires_in_seconds == nullptr) {
        syslog(LOG_ERR, "credential_expires_in_seconds is null");
        goto out;
    }

    rc = get_kerberos_service_ticket(
        file_endpoint_uri,
        oauth_token,
        expiration,
        session_key,
        krb_ticket
    );

    if (rc != 0) {
        goto out;
    }

    decoded_pair = decodeBase64(krb_ticket);
    decoded = decoded_pair.first;
    size = decoded_pair.second;
    rc = smb_insert_credential(file_endpoint_uri, decoded.c_str(), size, user_uid);

    syslog(LOG_INFO, "insert credential rc: %d", rc);

    if (rc != 0) {
        goto out;
    }

    closelog();
    return 0;

    out:
        closelog();
        return -1;
}

int smb_clear_credential(const std::string& file_endpoint_uri, uid_t user_uid) {
    krb5_context context = NULL;
    krb5_ccache ccache;
    krb5_principal principal;
    krb5_error_code krb_rc;
    krb5_creds creds;
    std::string krb5_cc_name_str;
    std::string krb5_cc_name_construct;
    const char* KRB5_CC_NAME;
    krb5_principal cache_principal;
    const krb5_data* realm_data;
    std::string realm;
    std::string service_principal;

    std::string endpoint_uri_str(file_endpoint_uri);
    if (endpoint_uri_str.substr(0, 8) == "https://") {
        endpoint_uri_str.replace(0, 8, "cifs/");
    } else {
        syslog(LOG_ERR, "file_endpoint_uri is not prefixed with 'https://'. file_endpoint_uri provided: %s", file_endpoint_uri.c_str());
	std::cerr << "file_endpoint_uri is not prefixed with 'https://'. Provided: " << file_endpoint_uri << std::endl;
        return -1;
    }

    // Use read_config_value to get the value of KRB5_CC_NAME
    krb5_cc_name_str = read_config_value("KRB5_CC_NAME");

    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    syslog(LOG_INFO,"Clear credential for %s", endpoint_uri_str.c_str());

    if (krb5_cc_name_str.empty()) {
        syslog(LOG_INFO, "Failed to read KRB5_CC_NAME from config file at %s", CONFIG_FILE_PATH);
        syslog(LOG_INFO, "Defaulting to default ccache for azfilesuser with UID: %d", user_uid);
        krb5_cc_name_construct = "FILE:/tmp/krb5cc_" + std::to_string(user_uid);
    } else {
        krb5_cc_name_construct = krb5_cc_name_str;
    }
    KRB5_CC_NAME = krb5_cc_name_construct.c_str();

    if (&endpoint_uri_str == nullptr || endpoint_uri_str.empty()) {
        syslog(LOG_ERR, "file_endpoint_uri is empty");
        goto out;
    }

    syslog(LOG_INFO, "KRB5_CC_NAME: %s", KRB5_CC_NAME);

    // TODO convert file_endpoint_uri to cifs/...

    krb_rc = krb5_init_context(&context);
    if (krb_rc) {
        syslog(LOG_ERR, "krb5_init_context() failed: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }

    krb_rc = krb5_cc_resolve(context, KRB5_CC_NAME, &ccache);
    if (krb_rc) {
        syslog(LOG_ERR, "krb5_cc_resolve() failed: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }
   // Get the principal from the credential cache
   krb_rc = krb5_cc_get_principal(context, ccache, &cache_principal);
   if (krb_rc) {
       syslog(LOG_ERR, "krb5_cc_get_principal() failed: %s", krb5_get_error_message(context, krb_rc));
       goto out;
   }

   // Extract the REALM from the credential cache principal
   realm_data = krb5_princ_realm(context, cache_principal);
   if (realm_data == NULL) {
       syslog(LOG_ERR, "Failed to get realm data from principal");
       goto out;
   }
   realm = std::string(realm_data->data, realm_data->length);

   // Compose the service principal using the endpoint and the extracted realm
   service_principal = endpoint_uri_str + "@" + realm;
   syslog(LOG_INFO, "Constructed service principal: %s", service_principal.c_str());

    // Parse the service principal
    krb_rc = krb5_parse_name(context, service_principal.c_str(), &principal);
    if (krb_rc) {
        syslog(LOG_ERR, "Failed to parse principal: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }

    memset(&creds, 0, sizeof(creds));
    creds.server = principal;

    krb_rc = krb5_cc_remove_cred(context, ccache, KRB5_TC_MATCH_SRV_NAMEONLY, &creds);
    if (krb_rc) {
        syslog(LOG_ERR, "krb5_cc_remove_cred() failed: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }

    syslog(LOG_INFO, "Removed creds for service principal: %s", parse_principal_into_string(principal).c_str());

    closelog();
    return 0;

    out:
    printf("Error clearing credential, check /var/log/syslog for more information.\n");

    if(cache_principal) {
        krb5_free_principal(context, cache_principal);
    }
    if (principal) {
        krb5_free_principal(context, principal);
    }
    if (context) {
        krb5_free_context(context);
    }
    closelog();
    return -1;
}

// List the credentials in the credential cache from KRB5_CC_NAME
void smb_list_credential(bool is_json, uid_t user_uid) {
    krb5_context context = NULL;
    krb5_ccache ccache;
    krb5_error_code krb_rc;
    krb5_principal principal;
    krb5_creds creds;
    krb5_creds **creds_array;
    krb5_cc_cursor cursor;
    int count = 0;
    std::ostringstream json_output;
    bool first = true;
    std::string krb5_cc_name_str;
    std::string krb5_cc_name_construct;
    const char* KRB5_CC_NAME;
    char *server_name = NULL;
    krb5_error_code ret;

    // Use read_config_value to get the value of KRB5_CC_NAME
    krb5_cc_name_str = read_config_value("KRB5_CC_NAME");

    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    if (krb5_cc_name_str.empty()) {
        syslog(LOG_INFO, "Failed to read KRB5_CC_NAME from config file at %s", CONFIG_FILE_PATH);
        syslog(LOG_INFO, "Defaulting to default ccache for azfilesuser with UID: %d", user_uid);
        krb5_cc_name_construct = "FILE:/tmp/krb5cc_" + std::to_string(user_uid);
    } else {
        krb5_cc_name_construct = krb5_cc_name_str;
    }
    KRB5_CC_NAME = krb5_cc_name_construct.c_str();

    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    krb_rc = krb5_init_context(&context);
    if (krb_rc) {
        syslog(LOG_ERR, "krb5_init_context() failed: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }

    krb_rc = krb5_cc_resolve(context, KRB5_CC_NAME, &ccache);
    if (krb_rc) {
        syslog(LOG_ERR, "krb5_cc_resolve() failed: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }

    krb_rc = krb5_cc_start_seq_get(context, ccache, &cursor);
    if (krb_rc) {
        syslog(LOG_ERR, "krb5_cc_start_seq_get() failed: %s", krb5_get_error_message(context, krb_rc));
        goto out;
    }

    syslog(LOG_INFO, "Listing credentials in credential cache %s", KRB5_CC_NAME);

    if (is_json) {
        json_output << "[\n";
    }

    while (krb5_cc_next_cred(context, ccache, &cursor, &creds) == 0) {
        if (creds.server->data->data && std::string(creds.server->data->data, creds.server->data->length) == "cifs") {
            count++;

            ret = krb5_unparse_name(context, creds.server, &server_name);
            if (ret) {
                syslog(LOG_ERR, "krb5_unparse_name failed: %s", krb5_get_error_message(context, ret));
                goto out;
            }
            
            if (is_json) {
                if (!first) {
                    json_output << ",\n"; // Add a comma between JSON objects
                }
                first = false;
                json_output << "  {\n"
                << "    \"server\": \"" << server_name << "\",\n"
                << "    \"client\": \"" << std::string(creds.client->data->data, creds.client->data->length) << "\",\n"
                << "    \"realm\": \"" << std::string(creds.server->realm.data, creds.server->realm.length) << "\",\n"
                << "    \"ticket_flags\": " << creds.ticket_flags << ",\n"
                << "    \"ticket_renew_till\": " << creds.times.renew_till << "\n"
                << "  }";
            } else {
                std::cout << "Credential " << count << ":" << std::endl;
                std::cout << "  Server: " << server_name << std::endl;
                std::cout << "  Client: " << std::string(creds.client->data->data, creds.client->data->length) << std::endl;
                std::cout << "  Realm: " << std::string(creds.server->realm.data, creds.server->realm.length) << std::endl;
                std::cout << "  Ticket flags: " << creds.ticket_flags << std::endl;
                std::cout << "  Ticket renew till: " << creds.times.renew_till << std::endl;
            }
            krb5_free_unparsed_name(context, server_name);
        }
    }
    
    if (is_json) {
        json_output << "\n]"; // End JSON array
        std::cout << json_output.str() << std::endl; // Print full JSON output
    }

    out:
    if (context) {
        krb5_free_context(context);
    }
    return;
}

int extern_smb_set_credential_oauth_token(char* file_endpoint_uri,
                        char* oauth_token,
                        unsigned int* credential_expires_in_seconds) 
{
    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    std::string user_uid_str = read_config_value("USER_UID");
    if (user_uid_str.empty()) {
        syslog(LOG_ERR, "Failed to read USER_UID from config file at %s", CONFIG_FILE_PATH);
        return -1;
    }

    uid_t user_uid = static_cast<uid_t>(std::stoi(user_uid_str));
    uid_t prev_uid = geteuid();
    if (seteuid(user_uid) != 0) {
        syslog(LOG_ERR, "Failed to switch to user UID %d: %s", user_uid, strerror(errno));
        return -1;
    }
    
    int rc = smb_set_credential_oauth_token(file_endpoint_uri, oauth_token, credential_expires_in_seconds, user_uid);
    seteuid(prev_uid);

    return rc;
}

int extern_smb_clear_credential(char* file_endpoint_uri) {
    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);
    
    std::string user_uid_str = read_config_value("USER_UID");
    if (user_uid_str.empty()) {
        syslog(LOG_ERR, "Failed to read USER_UID from config file at %s", CONFIG_FILE_PATH);
        printf("Failed to read USER_UID from config file at %s\n", CONFIG_FILE_PATH);
        return -1;
    }

    uid_t user_uid = static_cast<uid_t>(std::stoi(user_uid_str));
    uid_t prev_uid = geteuid();
    if (seteuid(user_uid) != 0) {
        syslog(LOG_ERR, "Failed to switch to user UID %d: %s", user_uid, strerror(errno));
        printf("Failed to switch to user UID %d: %s\n", user_uid, strerror(errno));
        return -1;
    }

    if (file_endpoint_uri == nullptr || strlen(file_endpoint_uri) == 0) {
        syslog(LOG_ERR, "file_endpoint_uri is empty");
        printf("file_endpoint_uri is empty\n");
        return -1;
    }

    int rc = smb_clear_credential(file_endpoint_uri, user_uid);
    seteuid(prev_uid);

    return rc;
}

void extern_smb_list_credential(bool is_json) {
    closelog();
    openlog("azfilesauth", LOG_PID | LOG_CONS, LOG_USER);

    std::string user_uid_str = read_config_value("USER_UID");
    if (user_uid_str.empty()) {
        syslog(LOG_ERR, "Failed to read USER_UID from config file at %s", CONFIG_FILE_PATH);
        printf("Failed to read USER_UID from config file at %s\n", CONFIG_FILE_PATH);
        return;
    }

    uid_t user_uid = static_cast<uid_t>(std::stoi(user_uid_str));
    uid_t prev_uid = geteuid();
    if (seteuid(user_uid) != 0) {
        syslog(LOG_ERR, "Failed to switch to user UID %d: %s", user_uid, strerror(errno));
        printf("Failed to switch to user UID %d: %s\n", user_uid, strerror(errno));
        return;
    }

    smb_list_credential(is_json, user_uid);
    seteuid(prev_uid);
}
