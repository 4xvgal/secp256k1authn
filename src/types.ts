export interface DerivedKey {
  privKey: Uint8Array;
  pubKey: Uint8Array;
  path: string;
}

export interface AuthKeyParams {
  rpId: string;
  deviceId?: number;
  keyIndex?: number;
  version?: number;
}

export interface RootContext {
  deriveAuthKey(params: AuthKeyParams): Promise<DerivedKey> | DerivedKey;
}
