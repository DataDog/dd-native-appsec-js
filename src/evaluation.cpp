/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#define NAPI_VERSION  8
#include <napi.h>
#include <ddwaf.h>

#include <cstring>

#include "src/evaluation.h"
#include "src/log.h"
#include "src/convert.h"

// Result map key lengths, used to reject a candidate before any memcmp.
constexpr size_t EVENTS_LEN = 6;
constexpr size_t ACTIONS_LEN = 7;
constexpr size_t ATTRIBUTES_LEN = 10;
constexpr size_t KEEP_LEN = 4;
constexpr size_t DURATION_LEN = 8;
constexpr size_t TIMEOUT_LEN = 7;
constexpr size_t EVALUATED_LEN = 9;

struct DDWAFObjectGuard {
  ddwaf_object* object;
  ddwaf_allocator alloc;

  ~DDWAFObjectGuard() {
    ddwaf_object_destroy(object, alloc);
  }
};

static DDWAF_RET_CODE do_eval(ddwaf_context target, ddwaf_object* data, ddwaf_allocator alloc,
                              ddwaf_object* result, uint64_t timeout) {
  return ddwaf_context_eval(target, data, alloc, result, timeout);
}

static DDWAF_RET_CODE do_eval(ddwaf_subcontext target, ddwaf_object* data, ddwaf_allocator alloc,
                              ddwaf_object* result, uint64_t timeout) {
  return ddwaf_subcontext_eval(target, data, alloc, result, timeout);
}

template <typename T>
static Napi::Object eval_and_build_result_impl(
  Napi::Env env,
  ddwaf_object* input,
  T target,
  ddwaf_allocator alloc,
  WAFTruncationMetrics* metrics,
  uint64_t timeout
) {
  // Keep the result destroyable when libddwaf does not write it.
  ddwaf_object result;
  ddwaf_object_set_invalid(&result);

  DDWAF_RET_CODE code = do_eval(target, input, alloc, &result, timeout);
  DDWAFObjectGuard result_guard{&result, alloc};

  // Ownership of the input depends on the return code: on DDWAF_ERR_INVALID_ARGUMENT
  // libddwaf never took it, on DDWAF_ERR_INVALID_OBJECT it has already freed it,
  // on DDWAF_ERR_INTERNAL ownership is undefined so it is left alone, and
  // otherwise the (sub)context owns it until it is destroyed.
  if (code == DDWAF_ERR_INVALID_ARGUMENT) {
    ddwaf_object_destroy(input, alloc);
  }

  Napi::Object res = Napi::Object::New(env);
  if (env.IsExceptionPending()) {
    return res;
  }

  Napi::Object metrics_js = Napi::Object::New(env);
  if (env.IsExceptionPending()) {
    return res;
  }

  if (!define_own_property(res, "metrics", metrics_js)) {
    return res;
  }

  if (metrics->max_truncated_string_length > 0) {
    if (!define_own_property(metrics_js, "maxTruncatedString",
                             Napi::Number::New(env, metrics->max_truncated_string_length))) {
      return res;
    }
  }

  if (metrics->max_truncated_container_size > 0) {
    if (!define_own_property(metrics_js, "maxTruncatedContainerSize",
                             Napi::Number::New(env, metrics->max_truncated_container_size))) {
      return res;
    }
  }

  if (metrics->max_truncated_container_depth > 0) {
    if (!define_own_property(metrics_js, "maxTruncatedContainerDepth",
                             Napi::Number::New(env, metrics->max_truncated_container_depth))) {
      return res;
    }
  }

  if (metrics->truncated_by_node_limit) {
    if (!define_own_property(metrics_js, "truncatedByNodeLimit", Napi::Boolean::New(env, true))) {
      return res;
    }
  }

  if (metrics->truncated_by_byte_limit) {
    if (!define_own_property(metrics_js, "truncatedByByteLimit", Napi::Boolean::New(env, true))) {
      return res;
    }
  }

  switch (code) {
    case DDWAF_ERR_INTERNAL:
    case DDWAF_ERR_INVALID_OBJECT:
    case DDWAF_ERR_INVALID_ARGUMENT:
      if (!define_own_property(res, "errorCode", Napi::Number::New(env, code))) {
        return res;
      }
      return res;
    default:
      break;
  }

  const ddwaf_object *run_timeout = nullptr, *duration = nullptr, *attributes = nullptr,
                     *events = nullptr, *actions = nullptr, *keep = nullptr,
                     *evaluated = nullptr;

  size_t result_size = ddwaf_object_get_size(&result);
  for (size_t i = 0; i < result_size; ++i) {
    const ddwaf_object* entry_key = ddwaf_object_at_key(&result, i);
    const ddwaf_object* entry_value = ddwaf_object_at_value(&result, i);
    if (entry_key == nullptr || entry_value == nullptr) {
      continue;
    }

    size_t length = 0;
    const char* name = ddwaf_object_get_string(entry_key, &length);
    if (name == nullptr) {
      continue;
    }

    if (length == TIMEOUT_LEN && memcmp(name, "timeout", TIMEOUT_LEN) == 0) {
      run_timeout = entry_value;
    } else if (length == DURATION_LEN && memcmp(name, "duration", DURATION_LEN) == 0) {
      duration = entry_value;
    } else if (length == ATTRIBUTES_LEN && memcmp(name, "attributes", ATTRIBUTES_LEN) == 0) {
      attributes = entry_value;
    } else if (length == EVENTS_LEN && memcmp(name, "events", EVENTS_LEN) == 0) {
      events = entry_value;
    } else if (length == ACTIONS_LEN && memcmp(name, "actions", ACTIONS_LEN) == 0) {
      actions = entry_value;
    } else if (length == KEEP_LEN && memcmp(name, "keep", KEEP_LEN) == 0) {
      keep = entry_value;
    } else if (length == EVALUATED_LEN && memcmp(name, "evaluated", EVALUATED_LEN) == 0) {
      evaluated = entry_value;
    }
  }

  if (run_timeout != nullptr && ddwaf_object_is_bool(run_timeout)) {
    mlog("Set timeout");
    if (!define_own_property(
          res, "timeout", Napi::Boolean::New(env, ddwaf_object_get_bool(run_timeout)))) {
      return res;
    }
  }

  if (duration != nullptr && ddwaf_object_is_unsigned(duration)) {
    uint64_t duration_value = ddwaf_object_get_unsigned(duration);
    if (duration_value > 0) {
      mlog("Set duration");
      if (!define_own_property(res, "duration", Napi::Number::New(env, duration_value))) {
        return res;
      }
    }
  }

  if (attributes != nullptr && ddwaf_object_get_size(attributes) > 0) {
    mlog("Set attributes");
    if (!define_own_property(res, "attributes", from_ddwaf_object(attributes, env))) {
      return res;
    }
  }

  if (code == DDWAF_MATCH) {
    mlog("ddwaf result is a match")
    if (!define_own_property(res, "status", Napi::String::New(env, "match"))) {
      return res;
    }

    if (events != nullptr) {
      mlog("Set events")
      if (!define_own_property(res, "events", from_ddwaf_object(events, env))) {
        return res;
      }
    }

    if (actions != nullptr) {
      mlog("Set actions")
      if (!define_own_property(res, "actions", from_ddwaf_object(actions, env))) {
        return res;
      }
    }
  }

  if (keep != nullptr && ddwaf_object_is_bool(keep)) {
    mlog("Set keep")
    if (!define_own_property(res, "keep", Napi::Boolean::New(env, ddwaf_object_get_bool(keep)))) {
      return res;
    }
  }

  if (evaluated != nullptr && ddwaf_object_is_unsigned(evaluated)) {
    mlog("Set evaluated")
    if (!define_own_property(
          res, "evaluated", Napi::Number::New(env, ddwaf_object_get_unsigned(evaluated)))) {
      return res;
    }
  }

  return res;
}

Napi::Object eval_and_build_result(
  Napi::Env env,
  ddwaf_object* input,
  ddwaf_context target,
  ddwaf_allocator alloc,
  WAFTruncationMetrics* metrics,
  uint64_t timeout
) {
  return eval_and_build_result_impl(env, input, target, alloc, metrics, timeout);
}

Napi::Object eval_and_build_result(
  Napi::Env env,
  ddwaf_object* input,
  ddwaf_subcontext target,
  ddwaf_allocator alloc,
  WAFTruncationMetrics* metrics,
  uint64_t timeout
) {
  return eval_and_build_result_impl(env, input, target, alloc, metrics, timeout);
}

// Returns false with a pending JS exception when the arguments are invalid, in
// which case the caller must return without throwing again.
bool validate_run_args(const Napi::CallbackInfo& info, const char* disposed_message,
                       bool disposed, int64_t* timeout) {
  Napi::Env env = info.Env();

  if (disposed) {
    Napi::Error::New(env, disposed_message).ThrowAsJavaScriptException();
    return false;
  }

  if (info.Length() < 2) {
    Napi::Error::New(env, "Wrong number of arguments, 2 expected").ThrowAsJavaScriptException();
    return false;
  }

  if (!info[0].IsObject() || info[0].IsArray() || info[0].IsFunction()) {
    Napi::TypeError::New(env, "Data must be an object").ThrowAsJavaScriptException();
    return false;
  }

  if (!info[1].IsNumber()) {
    Napi::TypeError::New(env, "Timeout argument must be a number").ThrowAsJavaScriptException();
    return false;
  }

  *timeout = info[1].ToNumber().Int64Value();
  if (*timeout <= 0) {
    Napi::TypeError::New(env, "Timeout argument must be greater than 0").ThrowAsJavaScriptException();
    return false;
  }

  return true;
}
