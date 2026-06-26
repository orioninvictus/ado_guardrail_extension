const path = require("path");

module.exports = {
    entry: "./index.tsx",
    output: {
        filename: "index.js",
        path: path.resolve(__dirname, "../../dist/report-tab"),
    },
    resolve: {
        extensions: [".ts", ".tsx", ".js"]
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
                exclude: /node_modules/,
            }
        ],
    }
};