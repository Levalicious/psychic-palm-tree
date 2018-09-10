package org.levk.p2pnet;

import org.bouncycastle.util.encoders.Hex;
import org.levk.SchnorrCode.crypto.SchnorrKey;
import static org.levk.p2pnet.util.HashUtil.blake2;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import static org.levk.p2pnet.util.ByteUtils.*;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        SecureRandom rand = new SecureRandom();
        byte[] randDat = new byte[1024 * 1024];

        System.out.println(Arrays.equals(randDat, deblobify(semideblobify(semiblobify(randDat)))));
    }

    public static ArrayList<byte[]> blobify(byte[] in) {
        int chunkCount = (int)Math.ceil((double)in.length / (double)255);

        ArrayList<byte[]> blob = new ArrayList<byte[]>();
        int processed = 0;
        for (int i = 0; i < chunkCount; i++) {
            byte[] chunk = new byte[256];

            for (int j = 0; j < 256; j++) {
                if (j == 0) {
                    if (in.length - 255 > i * 255) {
                        chunk[j] = (byte)0x00;
                    } else {
                        byte count = (byte)((byte)(in.length - processed) & (byte)0xFF);
                        chunk[j] = count;
                    }
                } else {
                    if (processed < in.length) {
                        chunk[j] = in[processed];
                        processed++;
                    } else {
                        chunk[j] = (byte)0x00;
                    }
                }
            }

            blob.add(chunk);
        }

        return blob;
    }

    public static byte[] deblobify(ArrayList<byte[]> in) {
        byte[] temp = new byte[0];

        for (int i = 0; i < in.size(); i++) {
            byte[] current = in.get(i);

            if (current[0] == 0x00) {
                temp = merge(temp, org.bouncycastle.util.Arrays.copyOfRange(current, 1, 256));
            } else {
                int dist = current[0];
                temp = merge(temp, org.bouncycastle.util.Arrays.copyOfRange(current, 1, dist + 1));
            }
        }

        return temp;
    }

    public static byte[] semiblobify(byte[] in) {
        ArrayList<byte[]> temp = blobify(in);

        byte[] tempBytes = new byte[0];

        for (int i = 0; i < temp.size(); i++) {
            tempBytes = merge(tempBytes, temp.get(i));
        }

        return tempBytes;
    }

    public static ArrayList<byte[]> semideblobify(byte[] in) {
        byte[][] temp = partition(in, 256);
        ArrayList<byte[]> tempList = new ArrayList<>();

        for (int i = 0; i < temp.length; i++) {
            tempList.add(temp[i]);
        }

        return tempList;
    }

    public static byte[][] partition(byte[] in, int partitionSize) {
        int partitionCount = (int)Math.ceil((double)in.length / (double)partitionSize);

        byte[][] temp = new byte[partitionCount][partitionSize];

        for (int i = 0; i < partitionCount; i++) {
            if (in.length < (partitionSize * (i + 1))) {
                temp[i] = new byte[(in.length - (partitionSize * i))];
            }

            for(int j = 0; (j < partitionSize && (partitionSize * i + j) < in.length); j++) {
                temp[i][j] = in[(partitionSize * i + j)];
            }
        }

        return temp;
    }
}
