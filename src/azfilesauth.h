#ifndef AZAUTHENTICATOR_H
#define AZAUTHENTICATOR_H

#include <string>
#include <iostream>

#define USER_AGENT "AzureFilesSmbAuth"
#define ACCEPT_TYPES "Accept: */*"                      // Equivalent to WINHTTP_DEFAULT_ACCEPT_TYPES
#define API_VERSION "x-ms-version: 2024-05-04"          // YYYY-DD-MM
#define AUTHORIZATION_HEADER "Authorization: Bearer "   // space to add oauth token
#define X_MS_DATE_HEADER "x-ms-date: "                  // space to add date
#define KRB5_CLIENT_PRINCIPAL "AzureFileClient"         // Server-side hard coded client principal
#define DEFAULT_CURL_CONNECT_TIMEOUT 10L
#define DEFAULT_CURL_TOTAL_TIMEOUT 30L

#define CONFIG_FILE_PATH "/etc/azfilesauth/config.yaml"

#ifdef __cplusplus
extern "C" {
#endif

    int extern_smb_set_credential_oauth_token(char* file_endpoint_uri,
                            char* auth_token,
                            unsigned int* credential_expires_in_seconds);
    int extern_smb_clear_credential(char* file_endpoint_uri);

    void extern_smb_list_credential(bool is_json);

#ifdef __cplusplus
}
#endif

#endif // AZAUTHENTICATOR_H
