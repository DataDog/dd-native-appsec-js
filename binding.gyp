
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
      "src/convert.cpp",
      "src/main.cpp"
    ],
    "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
    "cflags": [
      "-ffunction-sections",
      "-fdata-sections",
      "-fvisibility=hidden",
      "-Os",
      "-flto",
      "-fno-rtti"
    ],
    "cflags_cc": [
      "-ffunction-sections",
      "-fdata-sections",
      "-fvisibility=hidden",
      "-Os",
      "-flto",
      "-fno-rtti"
    ],
    "ldflags": [
      "-flto",
      "-Wl,--gc-sections",
      "-Wl,--exclude-libs,ALL"
    ],
    "xcode_settings": {
      "MACOSX_DEPLOYMENT_TARGET": "10.10",
      "OTHER_LDFLAGS": ["-Wl,-S", "-Wl,-dead_strip"],
      "DEPLOYMENT_POSTPROCESSING": "YES",
      "STRIP_INSTALLED_PRODUCT": "YES",
      "GCC_SYMBOLS_PRIVATE_EXTERN": "YES",
      "GCC_OPTIMIZATION_LEVEL": "s",
      "LLVM_LTO": "YES"
    },
    "conditions": [
      ["OS == 'linux'", {
        'ldflags': ['-Wl,--rpath=\$$ORIGIN', '-Wl,--strip-all', '-Wl,--gc-sections', '-Wl,--exclude-libs,ALL']
      }],
      ["OS == 'win'", {
        "libraries": ["Ws2_32.lib"],
        "cflags": [
          "/WX",
          "/O1",
          "/GL",
          "/Gy",
          "/GR-"
        ],
        "ldflags": [
          "/LTCG",
          "/OPT:REF",
          "/OPT:ICF"
        ],
        "msvs_settings": {
          "VCCLCompilerTool": {
            "Optimization": 1,
            "FavorSizeOrSpeed": 2,
            "WholeProgramOptimization": "true"
          },
          "VCLinkerTool": {
            "OptimizeReferences": 2,
            "EnableCOMDATFolding": 2,
            "LinkTimeCodeGeneration": 1
          }
        }
      }]
    ]
  }]
}
