module.exports = {
  "plugins": [
    "@babel/plugin-proposal-class-properties",
    ["@babel/plugin-proposal-decorators", {decoratorsBeforeExport: true}],
    "@babel/plugin-proposal-do-expressions",
    "@babel/plugin-proposal-export-default-from",
    "@babel/plugin-proposal-export-namespace-from",
    "@babel/plugin-proposal-function-bind",
    "@babel/plugin-proposal-function-sent",
    "@babel/plugin-proposal-json-strings",
    "@babel/plugin-proposal-logical-assignment-operators",
    "@babel/plugin-proposal-nullish-coalescing-operator",
    "@babel/plugin-proposal-numeric-separator",
    "@babel/plugin-proposal-optional-chaining",
    ["@babel/plugin-proposal-pipeline-operator", {proposal: "minimal"}],
    "@babel/plugin-proposal-throw-expressions",
    "@babel/plugin-syntax-dynamic-import",
    "@babel/plugin-syntax-import-meta"

  ],
  "presets": [
    ["@babel/preset-env", {
      targets: "defaults",
      modules: "commonjs",
      exclude: ["@babel/plugin-transform-regenerator"],
    }]
  ]
}
