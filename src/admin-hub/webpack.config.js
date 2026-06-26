const path = require("path");

module.exports = {
    entry: "./index.tsx",
    output: {
        filename: "index.js",
        path: path.resolve(__dirname, "../../dist/admin-hub"),
    },
    resolve: {
        extensions: [".ts", ".tsx", ".js"],
        alias: {
            "azure-devops-extension-sdk": path.resolve("node_modules/azure-devops-extension-sdk")
        },
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
                exclude: /node_modules/,
            },
            {
                test: /\.css$/,
                use: ["style-loader", "css-loader"],
            }
        ],
    }
};