package com.akadatsky;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        try {
            testAes();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void testAes() {
        byte[] data = {1, 2, 3, 4};
        byte[] keyBytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
        byte[] nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
        byte[] header = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};

        //GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        EAXBlockCipher cipher = new EAXBlockCipher(new AESEngine());
        KeyParameter key = new KeyParameter(keyBytes);
        cipher.init(true/* encrypt */, new AEADParameters(key, 128 /* macSize */, nonce, header));

        int size = cipher.getOutputSize(data.length);
        byte[] result = new byte[size];
        int olen = cipher.processBytes(data, 0, data.length, result, 0);
        try {
            olen += cipher.doFinal(result, olen);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (olen < size) {
            byte[] tmp = new byte[olen];
            System.arraycopy(result, 0, tmp, 0, olen);
            result = tmp;
        }
        System.out.println("result: " + Arrays.toString(result));
    }

}
