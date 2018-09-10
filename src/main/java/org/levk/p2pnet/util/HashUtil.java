package org.levk.p2pnet.util;

import org.bouncycastle.jcajce.provider.digest.Blake2b;

import java.security.MessageDigest;
import java.util.Arrays;

public class HashUtil {
    public static byte[] blake2(byte[] input) {
        MessageDigest blake = new Blake2b.Blake2b256();
        return blake.digest(input);
    }

    public static byte[] blake2omit12(byte[] input) {
        byte[] hash = blake2(input);
        return Arrays.copyOfRange(hash, 12, hash.length);
    }
}