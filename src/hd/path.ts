import {
  DEFAULT_AUTH_VERSION,
  HARDENED_OFFSET,
  PURPOSE_AUTH,
} from "../constants";

export interface AuthPathResult {
  path: string;
  indices: number[];
}

/**
 * Build the hardened derivation path for an auth key.
 */
export function makeAuthPath(
  rpIndex: number,
  deviceId = 0,
  keyIndex = 0,
  version = DEFAULT_AUTH_VERSION,
): AuthPathResult {
  const purposeH = PURPOSE_AUTH + HARDENED_OFFSET;
  const versionH = version + HARDENED_OFFSET;
  const deviceH = deviceId + HARDENED_OFFSET;
  const rpH = rpIndex + HARDENED_OFFSET;

  const indices = [purposeH, versionH, deviceH, rpH, keyIndex];
  const path =
    `m/${PURPOSE_AUTH}'/${version}'/${deviceId}'/${rpIndex}'/${keyIndex}`;

  return { path, indices };
}
