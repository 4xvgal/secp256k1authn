import * as secp from "@noble/secp256k1";
import { HDKey } from "@scure/bip32";

import { makeAuthPath } from "../hd/path";
import { AuthKeyParams, DerivedKey } from "../types";
import { hashToIndex } from "../utils/hash";

export async function deriveAuthKeyFromRoot(
    root: HDKey,
    params: AuthKeyParams,
): Promise<DerivedKey> {
    const {rpId, deviceId = 0, keyIndex = 0, version} = params;
    const rpIndex = hashToIndex(rpId);
    const {path, indices} = makeAuthPath(rpIndex, deviceId, keyIndex, version);

    let node = root;
    
    for(const idx of indices) {
        node = node.deriveChild(idx);
    }

    if(!node.privateKey){
        throw new Error("Unable to derive private key (public-only root?)");
    }

    const privKey = node.privateKey;
    const pubKey = secp.getPublicKey(privKey, true);
    return ({privKey, pubKey, path})

}