/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_WAF_INTERNAL_H_
#define SRC_WAF_INTERNAL_H_

#include <napi.h>
#include <ddwaf.h>

#include <cstddef>
#include <string>

// libddwaf 2.x removed ddwaf_config, so regexes use an ordinary configuration document.
// Its namespaced path avoids Remote Config collisions and stays hidden from configPaths.
constexpr char OBFUSCATOR_CONFIG_PATH[] = "::/native-appsec/obfuscator";
constexpr size_t OBFUSCATOR_CONFIG_PATH_LEN = sizeof(OBFUSCATOR_CONFIG_PATH) - 1;

bool validate_config_path(Napi::Env env, const std::string& path);
bool configure_obfuscator(const Napi::CallbackInfo& info, ddwaf_builder builder);
bool validate_obfuscator_config(const ddwaf_object* config);

#endif  // SRC_WAF_INTERNAL_H_
