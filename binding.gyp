
{
  "targets": [{
    "target_name": "appsec",
    "sources": [
      "src/convert.cpp",
      "src/main.cpp"
    ],
    "include_dirs": [
      "src",
      "libddwaf-1.0.6-Darwin-x86_64-2efc246/include",
      "<!@(node -p \"require('node-addon-api').include\")"
    ],
    "libraries": [
      "<!(node -p \"require('./scripts/lib.js').lib\")"
    ],
    "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
    "xcode_settings": {
      "MACOSX_DEPLOYMENT_TARGET": "10.10",
      "OTHER_CFLAGS": [
        "-std=c++14",
        "-stdlib=libc++",
        "-Wall",
        "-Werror"
      ]
    },
    "conditions": [
      ["OS == 'linux'", {
        "cflags": [
          "-std=c++11",
          "-Wall",
          "-Werror"
        ],
        "cflags_cc": [
          "-Wno-cast-function-type"
        ]
      }],
      ["OS == 'win'", {
        "cflags": [
          "/WX"
        ]
      }]
    ]
  }]
}
