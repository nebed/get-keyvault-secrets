"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const util = require("util");
const core = __importStar(require("@actions/core"));
class KeyVaultActionParameters {
    getKeyVaultActionParameters(handler) {
        this.keyVaultName = core.getInput("keyvault");
        this.secretsFilter = core.getInput("secrets");
        this.secretsFilePath = core.getInput("secretsfile");
        if (!this.keyVaultName) {
            core.setFailed("Vault name not provided.");
        }
        if (this.secretsFilter && this.secretsFilePath) {
            core.setFailed("Both secretsFilter and secretsFilePath cannot be provided at the same time.");
        }
        if (!this.secretsFilter && !this.secretsFilePath) {
            core.setFailed("One of secretsFilter or secretsFilePath should be provided");
        }
        var azureKeyVaultDnsSuffix = handler.getCloudSuffixUrl("keyvaultDns").substring(1);
        this.keyVaultUrl = util.format("https://%s.%s", this.keyVaultName, azureKeyVaultDnsSuffix);
        return this;
    }
}
exports.KeyVaultActionParameters = KeyVaultActionParameters;
