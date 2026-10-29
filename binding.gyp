
{
  "targets": [{
    "target_name": "appsec",
    "include_dirs": [
      ".",
      "<!@(node -p \"require('./scripts/lib.js').includePath\")",
      "<!@(node -p \"require('node-addon-api').include\")"
    ],
    "libraries": [
      "<!@(node -p \"require('./scripts/lib.js').libPath\")"
    ],
    "sources": [
      "src/context.cpp",
      "src/convert.cpp",
      "src/evaluation.cpp",
      "src/main.cpp",
      "src/obfuscator.cpp",
      "src/waf_configuration.cpp",
      "src/waf_initialization.cpp"
    ],
    "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
    "xcode_settings": {
      "MACOSX_DEPLOYMENT_TARGET": "14.2.1",
    },
    "conditions": [
      ["OS == 'linux'", {
        "libraries": ["-lm"],
        'ldflags': ['-Wl,--rpath=\$$ORIGIN']
      }],
      ["OS == 'win'", {
        "libraries": ["Ws2_32.lib"],
        "cflags": [
          "/WX"
        ]
      }]
    ]
  }]
}
