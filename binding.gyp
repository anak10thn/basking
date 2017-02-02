{
  "targets": [
    {
      "target_name": "parser",
      "sources": [ "lib/parser.cc" ],
      "include_dirs": [
        "src",
        "<(module_root_dir)/src",
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
