/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#ifndef SRC_WAF_INTERNAL_H_
#define SRC_WAF_INTERNAL_H_

#include <napi.h>
#include <ddwaf.h>

#include <string>

// The caller owns the strings and must keep them alive until ddwaf_builder_init returns.
bool configure_obfuscator(const Napi::CallbackInfo& info, ddwaf_config* waf_config,
                           std::string* key_regex_str, std::string* value_regex_str);

#endif  // SRC_WAF_INTERNAL_H_
