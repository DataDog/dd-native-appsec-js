/**
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.
 **/
const TIMEOUT = 9999e3

function matchedValue (waf, data) {
  const context = waf.createContext()
  try {
    const result = context.run(data, TIMEOUT)
    return result.events[0].rule_matches[0].parameters[0].value
  } finally {
    context.dispose()
  }
}

module.exports = matchedValue
