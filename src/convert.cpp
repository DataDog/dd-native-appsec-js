/**
* Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
* This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
**/
#include <napi.h>
#include <napi-inl.h>
#include <ddwaf.h>

#include <charconv>
#include <cstdint>
#include <string>
#include <algorithm>

#include "src/convert.h"
#include "src/log.h"

static constexpr size_t WAF_MAX_TOTAL_NODES = 5120;
static constexpr size_t WAF_MAX_TOTAL_BYTES = 1048576;
static constexpr char EMPTY_BUFFER_BYTE = '\0';

static ddwaf_object* to_ddwaf_object_internal(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJSON,
  ObjectStack *stack,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc,
  bool node_already_charged
);

static bool query_utf8_length(Napi::Env env, Napi::Value value, size_t* length) {
  napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, length);
  if (status == napi_ok) {
    return true;
  }
  if (!env.IsExceptionPending()) {
    Napi::Error::New(env, "Could not read UTF-8 string length").ThrowAsJavaScriptException();
  }
  return false;
}

static bool request_exhausted(bool lim, const WAFTruncationMetrics* metrics) {
  return lim && metrics != nullptr && metrics->conversion_exhausted();
}

// Must run before charge_utf8_bytes; a value rejected by the byte budget still reports its length.
static void record_truncated_string_length(
  bool lim,
  WAFTruncationMetrics* metrics,
  size_t original_length
) {
  if (lim && metrics != nullptr && original_length > WAF_MAX_STRING_LENGTH) {
    metrics->max_truncated_string_length =
      std::max(metrics->max_truncated_string_length, original_length);
  }
}

ddwaf_object* to_ddwaf_object_array(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Array arr,
  int depth,
  bool lim,
  bool ignoreToJSON,
  ObjectStack *stack,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc
) {
  if (!ignoreToJSON) {
    Napi::Value toJSON = arr.Get("toJSON");
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      ddwaf_object_set_invalid(object);
      return nullptr;
    }
    if (toJSON.IsFunction()) {
      Napi::Value toJSONResult = toJSON.As<Napi::Function>().Call(arr, {});
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        env.GetAndClearPendingException();
        return ddwaf_object_set_invalid(object);
      }
      return to_ddwaf_object_internal(
        object, env, toJSONResult, depth, lim, true, stack, metrics, alloc, true);
    }
  }

  uint32_t len = arr.Length();
  if (lim && len > WAF_MAX_CONTAINER_SIZE) {
    if (metrics) {
      metrics->max_truncated_container_size = std::max(metrics->max_truncated_container_size,
                                                       static_cast<size_t>(len));
    }
    len = WAF_MAX_CONTAINER_SIZE;
  }

  // Reserve exact capacity because growth or promotion invalidates element pointers.
  if (ddwaf_object_set_array(object, len, alloc) == nullptr) {
    mlog("failed to create array");
    ddwaf_object_set_invalid(object);
    return nullptr;
  }

  for (uint32_t i = 0; i < len; ++i) {
    bool child_charged = false;
    if (lim && metrics != nullptr) {
      if (!metrics->charge_node(WAF_MAX_TOTAL_NODES)) {
        break;
      }
      child_charged = true;
    }

    Napi::Value item = arr.Get(i);
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      break;
    }
    ddwaf_object *slot = ddwaf_object_insert(object, alloc);
    if (slot == nullptr) {
      mlog("add to array failed");
      break;
    }
    to_ddwaf_object_internal(
      slot, env, item, depth, lim, false, stack, metrics, alloc, child_charged);
    if (env.IsExceptionPending() || request_exhausted(lim, metrics)) {
      break;
    }
  }

  return object;
}

ddwaf_object* to_ddwaf_object_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Object obj,
  int depth,
  bool lim,
  bool ignoreToJSON,
  ObjectStack *stack,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc
) {
  if (!ignoreToJSON) {
    Napi::Value toJSON = obj.Get("toJSON");
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      ddwaf_object_set_invalid(object);
      return nullptr;
    }
    if (toJSON.IsFunction()) {
      Napi::Value toJSONResult = toJSON.As<Napi::Function>().Call(obj, {});
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        env.GetAndClearPendingException();
        return ddwaf_object_set_invalid(object);
      }
      return to_ddwaf_object_internal(
        object, env, toJSONResult, depth, lim, true, stack, metrics, alloc, true);
    }
  }

  Napi::Array properties = obj.GetPropertyNames();
  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    ddwaf_object_set_invalid(object);
    return nullptr;
  }
  uint32_t len = properties.Length();
  if (lim && len > WAF_MAX_CONTAINER_SIZE) {
    if (metrics) {
      metrics->max_truncated_container_size = std::max(metrics->max_truncated_container_size,
                                                       static_cast<size_t>(len));
    }
    len = WAF_MAX_CONTAINER_SIZE;
  }

  // Reserve all property slots because growth invalidates pointers; skipped keys only leave spare capacity.
  if (ddwaf_object_set_map(object, len, alloc) == nullptr) {
    mlog("failed to create map");
    ddwaf_object_set_invalid(object);
    return nullptr;
  }

  for (uint32_t i = 0; i < len; ++i) {
    mlog("Getting properties");
    Napi::Value keyV = properties.Get(i);
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      break;
    }
    bool own_property = obj.HasOwnProperty(keyV);
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      break;
    }
    if (!own_property || !keyV.IsString()) {
      continue;
    }

    size_t key_length = 0;
    if (!query_utf8_length(env, keyV, &key_length)) {
      mlog("Exception pending");
      break;
    }

    bool child_charged = false;
    if (lim && metrics != nullptr) {
      if (!metrics->charge_utf8_bytes(key_length, WAF_MAX_TOTAL_BYTES) ||
          !metrics->charge_node(WAF_MAX_TOTAL_NODES)) {
        break;
      }
      child_charged = true;
    }

    Napi::Value valV = obj.Get(keyV);
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      break;
    }

    std::string key = keyV.As<Napi::String>().Utf8Value();
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      break;
    }

    mlog("Looping into ToPWArgs");
    ddwaf_object *slot = ddwaf_object_insert_key(object, key.c_str(),
                                                 static_cast<uint32_t>(key.length()), alloc);
    if (slot == nullptr) {
      mlog("add to object failed");
      break;
    }
    to_ddwaf_object_internal(
      slot, env, valV, depth, lim, false, stack, metrics, alloc, child_charged);
    if (env.IsExceptionPending() || request_exhausted(lim, metrics)) {
      break;
    }
  }

  return object;
}

ddwaf_object* to_ddwaf_string(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  bool lim,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc
) {
  size_t original_length = 0;
  if (!query_utf8_length(env, val, &original_length)) {
    return ddwaf_object_set_invalid(object);
  }
  record_truncated_string_length(lim, metrics, original_length);
  if (lim) {
    // Copy only a bounded UTF-8 prefix. N-API leaves a partial final code point
    // out, so charge the bytes actually copied rather than the source length.
    std::array<char, WAF_MAX_STRING_LENGTH + 1> buffer;
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, val, buffer.data(), buffer.size(), &length);
    if (status != napi_ok) {
      if (!env.IsExceptionPending()) {
        Napi::Error::New(env, "Could not read UTF-8 string").ThrowAsJavaScriptException();
      }
      return ddwaf_object_set_invalid(object);
    }
    if (metrics != nullptr && !metrics->charge_utf8_bytes(length, WAF_MAX_TOTAL_BYTES)) {
      return ddwaf_object_set_invalid(object);
    }
    return ddwaf_object_set_string(object, buffer.data(), static_cast<uint32_t>(length), alloc);
  }

  std::string str = val.As<Napi::String>().Utf8Value();
  if (env.IsExceptionPending()) {
    return ddwaf_object_set_invalid(object);
  }

  return ddwaf_object_set_string(object, str.c_str(), static_cast<uint32_t>(original_length), alloc);
}

static ddwaf_object* to_ddwaf_buffer(
  ddwaf_object* object,
  Napi::Value val,
  bool lim,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc
) {
  Napi::Buffer<uint8_t> buffer = val.As<Napi::Buffer<uint8_t>>();
  size_t original_length = buffer.Length();
  record_truncated_string_length(lim, metrics, original_length);
  size_t length = lim ? std::min(original_length, WAF_MAX_STRING_LENGTH) : original_length;
  if (lim && metrics != nullptr &&
      !metrics->charge_utf8_bytes(length, WAF_MAX_TOTAL_BYTES)) {
    return ddwaf_object_set_invalid(object);
  }

  const char* data = original_length == 0
    ? &EMPTY_BUFFER_BYTE
    : reinterpret_cast<const char*>(buffer.Data());
  return ddwaf_object_set_string(object, data, static_cast<uint32_t>(length), alloc);
}

static bool is_byte_typed_array(Napi::Value val) {
  // napi_is_buffer accepts any ArrayBufferView; this gate avoids casting DataView
  // and reinterpreting non-byte typed arrays as byte buffers.
  if (!val.IsTypedArray()) {
    return false;
  }
  napi_typedarray_type type = val.As<Napi::TypedArray>().TypedArrayType();
  return type == napi_uint8_array || type == napi_uint8_clamped_array;
}

static ddwaf_object* to_ddwaf_object_internal(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJson,
  ObjectStack *stack,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc,
  bool node_already_charged
) {
  mlog("starting to convert an object");
  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    return ddwaf_object_set_invalid(object);
  }
  if (lim && metrics != nullptr && !node_already_charged &&
      !metrics->charge_node(WAF_MAX_TOTAL_NODES)) {
    return ddwaf_object_set_invalid(object);
  }
  if (depth >= static_cast<int>(WAF_MAX_CONTAINER_DEPTH)) {
    mlog("Max depth reached");
    if (metrics) {
      metrics->max_truncated_container_depth = std::max(metrics->max_truncated_container_depth,
                                                        static_cast<size_t>(depth));
    }
    return ddwaf_object_set_map(object, 0, alloc);
  }
  if (val.IsNull()) {
    mlog("creating Null");
    return ddwaf_object_set_null(object);
  }
  if (val.IsString()) {
    mlog("creating String");
    return to_ddwaf_string(object, env, val, lim, metrics, alloc);
  }
  if (is_byte_typed_array(val)) {
    mlog("creating Buffer");
    return to_ddwaf_buffer(object, val, lim, metrics, alloc);
  }
  if (val.IsNumber()) {
    mlog("creating Number");
    return ddwaf_object_set_float(object, val.ToNumber().DoubleValue());
  }
  if (val.IsBoolean()) {
    mlog("creating Boolean");
    bool boolValue = val.ToBoolean().Value();
    return ddwaf_object_set_bool(object, boolValue);
  }
  if (val.IsFunction()) {
    return ddwaf_object_set_invalid(object);
  }
  if (val.IsArray()) {
    if (stack->contains(val)) {
      mlog("Circular dependency")
      return ddwaf_object_set_invalid(object);
    }
    if (!stack->push(val)) {
      return ddwaf_object_set_invalid(object);
    }
    mlog("creating Array");
    auto result =
      to_ddwaf_object_array(object, env, val.ToObject().As<Napi::Array>(), depth + 1, lim, ignoreToJson, stack,
                            metrics, alloc);
    stack->pop();
    return result;
  }
  if (val.IsObject()) {
    if (stack->contains(val)) {
      mlog("Circular dependency")
      return ddwaf_object_set_invalid(object);
    }
    if (!stack->push(val)) {
      return ddwaf_object_set_invalid(object);
    }
    mlog("creating Object");
    auto result = to_ddwaf_object_object(object, env, val.ToObject(), depth + 1, lim, ignoreToJson, stack, metrics,
                                        alloc);
    stack->pop();
    return result;
  }
  mlog("creating invalid object");
  return ddwaf_object_set_invalid(object);
}

ddwaf_object* to_ddwaf_object(
  ddwaf_object *object,
  Napi::Env env,
  Napi::Value val,
  int depth,
  bool lim,
  bool ignoreToJson,
  ObjectStack *stack,
  WAFTruncationMetrics* metrics,
  ddwaf_allocator alloc
) {
  return to_ddwaf_object_internal(
    object, env, val, depth, lim, ignoreToJson, stack, metrics, alloc, false);
}

static constexpr napi_property_attributes OWN_DATA_PROPERTY_ATTRIBUTES =
  static_cast<napi_property_attributes>(napi_writable | napi_enumerable | napi_configurable);

static bool define_own_property(Napi::Object target, const Napi::PropertyDescriptor& descriptor) {
  Napi::Env env = target.Env();
  if (env.IsExceptionPending()) {
    return false;
  }

  bool defined = target.DefineProperty(descriptor);
  if (!defined && !env.IsExceptionPending()) {
    Napi::TypeError::New(env, "Could not define native property").ThrowAsJavaScriptException();
  }
  return defined && !env.IsExceptionPending();
}

bool define_own_property(Napi::Object target, const Napi::Name& name, Napi::Value value) {
  return define_own_property(
    target, Napi::PropertyDescriptor::Value(name, value, OWN_DATA_PROPERTY_ATTRIBUTES));
}

bool define_own_property(Napi::Object target, const char* name, Napi::Value value) {
  return define_own_property(
    target, Napi::PropertyDescriptor::Value(name, value, OWN_DATA_PROPERTY_ATTRIBUTES));
}

bool define_own_property(Napi::Object target, uint32_t index, Napi::Value value) {
  std::array<char, 11> name;
  char* end = std::to_chars(name.data(), name.data() + name.size() - 1, index).ptr;
  *end = '\0';
  return define_own_property(target, name.data(), value);
}

Napi::Value from_ddwaf_object(const ddwaf_object *object, Napi::Env env) {
  Napi::Value result;

  // libddwaf 2.x tags are not bitmasks. Use the public predicates and accessors.
  if (ddwaf_object_is_map(object)) {
    size_t size = ddwaf_object_get_size(object);
    Napi::Object obj = Napi::Object::New(env);
    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      return env.Undefined();
    }

    for (size_t i = 0; i < size; ++i) {
      const ddwaf_object* key = ddwaf_object_at_key(object, i);
      const ddwaf_object* value = ddwaf_object_at_value(object, i);
      if (key == nullptr || value == nullptr) {
        mlog("ddwaf map entry is null")
        continue;
      }

      size_t key_length = 0;
      const char* key_str = ddwaf_object_get_string(key, &key_length);
      if (key_str == nullptr) {
        mlog("ddwaf map key is not a string")
        continue;
      }

      Napi::String k = Napi::String::New(env, key_str, key_length);
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        return env.Undefined();
      }
      Napi::Value v = from_ddwaf_object(value, env);
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        return env.Undefined();
      }
      if (!define_own_property(obj, k, v)) {
        mlog("Exception pending");
        return env.Undefined();
      }
    }

    result = obj;
  } else if (ddwaf_object_is_array(object)) {
    size_t size = ddwaf_object_get_size(object);
    Napi::Array arr = Napi::Array::New(env, size);

    if (env.IsExceptionPending()) {
      mlog("Exception pending");
      return env.Undefined();
    }

    for (size_t i = 0; i < size; ++i) {
      const ddwaf_object* e = ddwaf_object_at_value(object, i);
      if (e == nullptr) {
        mlog("ddwaf array entry is null")
        continue;
      }
      Napi::Value v = from_ddwaf_object(e, env);
      if (env.IsExceptionPending()) {
        mlog("Exception pending");
        return env.Undefined();
      }
      if (!define_own_property(arr, static_cast<uint32_t>(i), v)) {
        mlog("Exception pending");
        return env.Undefined();
      }
    }

    result = arr;
  } else if (ddwaf_object_is_string(object)) {
    size_t length = 0;
    const char* str = ddwaf_object_get_string(object, &length);
    // libddwaf 2.x strings are length-delimited and may contain embedded NULs; always pass the length.
    result = str == nullptr ? env.Null() : Napi::String::New(env, str, length);
  } else if (ddwaf_object_is_bool(object)) {
    result = Napi::Boolean::New(env, ddwaf_object_get_bool(object));
  } else if (ddwaf_object_is_signed(object)) {
    result = Napi::Number::New(env, ddwaf_object_get_signed(object));
  } else if (ddwaf_object_is_unsigned(object)) {
    result = Napi::Number::New(env, ddwaf_object_get_unsigned(object));
  } else if (ddwaf_object_is_float(object)) {
    result = Napi::Number::New(env, ddwaf_object_get_float(object));
  } else {
    result = env.Null();
  }

  if (env.IsExceptionPending()) {
    mlog("Exception pending");
    return env.Undefined();
  }

  return result;
}
