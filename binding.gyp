
{
  "targets": [{
    "target_name": "appsec",
    "include_dirs": [
      ".",
      "<!@(node -p \"require('./scripts/lib.js').include\")",
      "<!@(node -p \"require('node-addon-api').include\")"
    ],
    "libraries": [
      "<!@(node -p \"require('./scripts/lib.js').lib\")"
    ],
    "sources": [
      "src/convert.cpp",
      "src/main.cpp"
    ],
    "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
    "xcode_settings": {
      "MACOSX_DEPLOYMENT_TARGET": "10.10",
    },
    "conditions": [
      ["OS == 'linux'", {
        'ldflags': ['-Wl,--rpath=\$$ORIGIN']
      }],
      ["OS == 'win'", {
        "cflags": [
          "/WX"
        ]
      }]
    ]
  }]
}
