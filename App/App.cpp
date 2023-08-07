#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#pragma GCC diagnostic ignored "-Wcast-qual"
#pragma GCC diagnostic ignored "-Wfloat-equal"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#include <lib/crow_all.h>
#pragma GCC diagnostic pop

#include <iomanip>
#include <iostream>
#include <pqxx/pqxx>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <sys/random.h> // for testing secp256k1-zkp. Can be removed after this.

#include "../utils/include_secp256k1_zkp_lib.h"
#include "../utils/strencodings.h"

#include "App.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_tcrypto.h"

# define ENCLAVE_FILENAME "enclave.signed.so"

// extracted from sdk/tseal/tSeal_util.cpp
uint32_t sgx_calc_sealed_data_size(const uint32_t add_mac_txt_size, const uint32_t txt_encrypt_size) 
{
    if(add_mac_txt_size > UINT32_MAX - txt_encrypt_size)
        return UINT32_MAX;
    uint32_t payload_size = add_mac_txt_size + txt_encrypt_size; //Calculate the payload size

    if(payload_size > UINT32_MAX - sizeof(sgx_sealed_data_t))
        return UINT32_MAX;
    return (uint32_t)(sizeof(sgx_sealed_data_t) + payload_size);
}

bool save_aggregated_key_data(
    char* sealed, size_t sealed_size, 
    unsigned char* aggregated_pubkey, size_t aggregated_pubkey_size,
    unsigned char* keyagg_cache, size_t keyagg_cache_size,
    std::string& error_message) 
{
    try
    {
        pqxx::connection conn("postgresql://postgres:postgres@localhost/sgx");
        if (conn.is_open()) {

            std::string create_table_query =
                "CREATE TABLE IF NOT EXISTS aggregated_key_data ( "
                "id SERIAL PRIMARY KEY, "
                "sealed_keypair BYTEA, "
                "aggregated_key BYTEA, "
                "cache BYTEA);";

            pqxx::work txn(conn);
            txn.exec(create_table_query);
            txn.commit();

            std::basic_string_view<std::byte> sealed_data_view(reinterpret_cast<std::byte*>(sealed), sealed_size);
            std::basic_string_view<std::byte> aggregated_pubkey_data_view(reinterpret_cast<std::byte*>(aggregated_pubkey), aggregated_pubkey_size);
            std::basic_string_view<std::byte> keyagg_cache_data_view(reinterpret_cast<std::byte*>(keyagg_cache), keyagg_cache_size);

            std::string insert_query =
                "INSERT INTO aggregated_key_data (sealed_keypair, aggregated_key, cache) VALUES ($1, $2, $3);";
            pqxx::work txn2(conn);

            txn2.exec_params(insert_query, sealed_data_view, aggregated_pubkey_data_view, keyagg_cache_data_view);
            txn2.commit();

            conn.close();
            return true;
        } else {
            error_message = "Failed to connect to the database!";
            return false;
        }
    }
    catch (std::exception const &e)
    {
        error_message = e.what();
        return false;
    }
}

bool load_aggregated_key_data(
    unsigned char* aggregated_pubkey, size_t aggregated_pubkey_size, 
    char* sealed_keypair, size_t sealed_keypair_size,
    unsigned char* keyagg_cache, size_t keyagg_cache_size,
    std::string& error_message) {
    try
    {
        pqxx::connection conn("postgresql://postgres:postgres@localhost/sgx");
        if (conn.is_open()) {

            std::basic_string_view<std::byte> aggregated_pubkey_data_view(reinterpret_cast<std::byte*>(aggregated_pubkey), aggregated_pubkey_size);

            std::string sealed_keypair_query =
                "SELECT sealed_keypair, cache FROM aggregated_key_data WHERE aggregated_key = $1;";
            
            pqxx::nontransaction ntxn(conn);

            conn.prepare("sealed_keypair_query", sealed_keypair_query);

            pqxx::result result = ntxn.exec_prepared("sealed_keypair_query", aggregated_pubkey_data_view);

            if (!result.empty()) {
                auto sealed_keypair_view = result[0]["sealed_keypair"].as<std::basic_string<std::byte>>();
                auto cache_view = result[0]["cache"].as<std::basic_string<std::byte>>();

                if (sealed_keypair_view.size() != sealed_keypair_size) {
                    error_message = "Failed to retrieve keypair. Different size than expected !";
                    return false;
                }

                if (cache_view.size() != keyagg_cache_size) {
                    error_message = "Failed to retrieve cache. Different size than expected !";
                    return false;
                }

                memcpy(sealed_keypair, sealed_keypair_view.data(), sealed_keypair_size);
                memcpy(keyagg_cache, cache_view.data(), keyagg_cache_size);
            }

            conn.close();
            return true;
        } else {
            error_message = "Failed to connect to the database!";
            return false;
        }
    }
    catch (std::exception const &e)
    {
        error_message = e.what();
        return false;
    }
}

/* ocall functions (untrusted) */
void ocall_print_string(const char *str)
{
    printf("%s\n", str);
}

void ocall_print_int(const char *str, const int *number)
{
    printf("%s%d\n", str, *number);
}

void ocall_print_hex(const unsigned char** key, const int *keylen)
{
    printf("%s\n", key_to_string(*key, *keylen).c_str());
}

int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    crow::SimpleApp app;

    sgx_enclave_id_t enclave_id = 0;
    std::mutex mutex_enclave_id; // protects map_aggregate_key_data

    {
        const std::lock_guard<std::mutex> lock(mutex_enclave_id);

        // initialize enclave
        sgx_status_t enclave_created = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
        if (enclave_created != SGX_SUCCESS) {
            printf("Enclave init error\n");
            return -1;
        }
    }

    CROW_ROUTE(app, "/key_aggregation")
        .methods("POST"_method)([&enclave_id, &mutex_enclave_id](const crow::request& req) {
            auto req_body = crow::json::load(req.body);
            if (!req_body)
                return crow::response(400);

            if (req_body.count("pubkey") == 0)
                return crow::response(400, "Invalid parameter. It must be 'pubkey'.");

            std::string client_pubkey_hex = req_body["pubkey"].s();

            // Check if the string starts with 0x and remove it if necessary
            if (client_pubkey_hex.substr(0, 2) == "0x") {
                client_pubkey_hex = client_pubkey_hex.substr(2);
            }

            std::vector<unsigned char> client_pubkey_serialized = ParseHex(client_pubkey_hex);

            // 1. Allocate memory for the aggregated pubkey and sealedprivkey.
            size_t server_pubkey_size = 33; // serialized compressed public keys are 33-byte array
            unsigned char server_pubkey[server_pubkey_size];

            size_t aggregated_pubkey_size = 32; // serialized compressed public keys are 33-byte array
            unsigned char aggregated_pubkey[aggregated_pubkey_size];

            size_t sealedprivkey_size = sgx_calc_sealed_data_size(0U, sizeof(secp256k1_keypair));
            std::vector<char> sealedprivkey(sealedprivkey_size);  // Using a vector to manage dynamic-sized array.

            const std::lock_guard<std::mutex> lock(mutex_enclave_id);

            secp256k1_musig_keyagg_cache keyagg_cache;

            sgx_status_t ecall_ret;
            sgx_status_t status = key_aggregation(
                enclave_id, &ecall_ret, 
                client_pubkey_serialized.data(), client_pubkey_serialized.size(),
                server_pubkey, server_pubkey_size,
                aggregated_pubkey, aggregated_pubkey_size, 
                keyagg_cache.data, sizeof(keyagg_cache.data),
                sealedprivkey.data(), sealedprivkey_size);
 
            if (ecall_ret != SGX_SUCCESS) {
                return crow::response(500, "Key aggregation Ecall failed ");
            }  if (status != SGX_SUCCESS) {
                return crow::response(500, "Key aggregation failed ");
            }

            auto server_seckey_hex = key_to_string(server_pubkey, server_pubkey_size);
            auto aggregated_pubkey_hex = key_to_string(aggregated_pubkey, aggregated_pubkey_size);
            
            std::string error_message;
            bool data_saved = save_aggregated_key_data(
                sealedprivkey.data(), sealedprivkey.size(), aggregated_pubkey, 32, keyagg_cache.data, sizeof(keyagg_cache), error_message);

            if (!data_saved) {
                error_message = "Failed to save aggregated key data: " + error_message;
                return crow::response(500, error_message);
            }

            crow::json::wvalue result({{"aggregated_pubkey", aggregated_pubkey_hex}, {"server_pubkey", server_seckey_hex}});
            return crow::response{result};
    });

    CROW_ROUTE(app, "/partial_signature")
        .methods("POST"_method)([&enclave_id, &mutex_enclave_id](const crow::request& req) {
            
            auto req_body = crow::json::load(req.body);
            if (!req_body)
                return crow::response(400);

            if (req_body.count("aggregated_pubkey") == 0 || 
                req_body.count("message_hash") == 0 ||
                req_body.count("pubnonce") == 0) {
                return crow::response(400, "Invalid parameters. They must be 'aggregated_pubkey' and 'message_hash'.");
            }

            std::string agg_pubkey_hex = req_body["aggregated_pubkey"].s();
            std::string message_hash = req_body["message_hash"].s();
            std::string client_pubnonce_hex = req_body["pubnonce"].s();

            if (agg_pubkey_hex.substr(0, 2) == "0x") {
                agg_pubkey_hex = agg_pubkey_hex.substr(2);
            }

            if (message_hash.substr(0, 2) == "0x") {
                message_hash = message_hash.substr(2);
            }

            if (client_pubnonce_hex.substr(0, 2) == "0x") {
                client_pubnonce_hex = client_pubnonce_hex.substr(2);
            }

            std::vector<unsigned char> serialized_aggregated_pubkey = ParseHex(agg_pubkey_hex);

            if (serialized_aggregated_pubkey.size() != 32) {
                return crow::response(400, "Invalid aggregated pubkey length. Must be 32 bytes (x-only)!");
            }

            size_t sealed_keypair_size = sgx_calc_sealed_data_size(0U, sizeof(secp256k1_keypair));
            std::vector<char> sealed_keypair(sealed_keypair_size);  // Using a vector to manage dynamic-sized array.

            secp256k1_musig_keyagg_cache keyagg_cache;

            std::string error_message;
            bool data_loaded = load_aggregated_key_data(
                serialized_aggregated_pubkey.data(), serialized_aggregated_pubkey.size(), 
                sealed_keypair.data(), sealed_keypair_size,
                keyagg_cache.data, sizeof(keyagg_cache), error_message);

            if (!data_loaded) {
                error_message = "Failed to load aggregated key data: " + error_message;
                return crow::response(500, error_message);
            }

            if (message_hash.size() != 64) {
                return crow::response(400, "Invalid message hash length. Must be 32 bytes!");
            }

            unsigned char msg[32];
            if (!hex_to_bytes(message_hash, msg)) {
                return crow::response(400, "Invalid message hash!");
            }

            if (client_pubnonce_hex.size() != 132) {
                return crow::response(400, "Invalid pubnonce length. Must be 66 bytes!");
            }

            std::vector<unsigned char> serialized_client_pubnonce = ParseHex(client_pubnonce_hex);

            const std::lock_guard<std::mutex> lock(mutex_enclave_id);
            sgx_status_t ecall_ret;

            unsigned char serialized_partial_sig[32];
            unsigned char serialized_server_pubnonce[66];

            partial_signature(
                enclave_id, &ecall_ret,
                serialized_client_pubnonce.data(), serialized_client_pubnonce.size(),
                msg, sizeof(msg),
                sealed_keypair.data(), sealed_keypair.size(),
                keyagg_cache.data, sizeof(keyagg_cache),
                serialized_partial_sig, 32,
                serialized_server_pubnonce, 66
            );

            auto pubnonce_hex = key_to_string(serialized_server_pubnonce, sizeof(serialized_server_pubnonce));
            auto partial_sig_hex = key_to_string(serialized_partial_sig, sizeof(serialized_partial_sig));

            crow::json::wvalue result({{"partial_sig", partial_sig_hex}, {"public_nonce", pubnonce_hex}});
            return crow::response{result};
    
    });

    app.port(18080).multithreaded().run();

    {
        const std::lock_guard<std::mutex> lock(mutex_enclave_id);
    
        // destroy the enclave
        sgx_destroy_enclave(enclave_id);
    }

    return 0;
}
