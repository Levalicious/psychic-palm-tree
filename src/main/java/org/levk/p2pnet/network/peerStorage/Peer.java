package org.levk.p2pnet.network.peerStorage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.util.encoders.Hex;
import org.levk.CrispyRotaryPhone.CRPENC;
import org.levk.CrispyRotaryPhone.ENCItem;
import org.levk.CrispyRotaryPhone.ENCList;
import org.levk.SchnorrCode.crypto.SchnorrKey;
import org.levk.SchnorrCode.crypto.SchnorrSig;
import org.xerial.snappy.Snappy;

import static org.levk.p2pnet.util.ByteUtils.*;
import static org.levk.p2pnet.util.HashUtil.*;

public class Peer {
    public final static byte[] IPv4inIPv6Prefix = Hex.decode("00000000000000000000FFFF");

    public final static int VERSION_LENGTH = 2;
    public final static int ADDRESS_LENGTH = 16;
    public final static int PORT_LENGTH = 2;

    /* The size of the input and output buffers for each peer */
    public final static int BUFFER_SIZE = 63792;

    /* Number of milliseconds to observe the number of 
     * messages during. Currently an hour. */
    public final static int RATE_REF = 1 * 60 * 60 * 1000;

    /* When this peer last sent a valid message.
     * more "active" peers are prioritized. */
    private long time;

    /* The client version that this peer is running */
    private byte[] version;

    /* The network address of this node. If IPv4,
     * it's an IPv4-mapped IPv6 address. Otherwise,
     * it's a plain IPv6 one */
    private byte[] address;

    /* The port upon which this node listens for
     * new connections */
    private byte[] port;

    /* The pubkey associated with this node */
    private byte[] pubkey;

    /* The address for putting this node into a bucket */
    private byte[] bucketAddr;

    /* Whether the signature signing the peer
     * data is valid AND the InetAddress this
     * node is connected to matches the 
     * encoded information. */
    private boolean valid;

    /* The timestamps for the N most recently witnessed 
     * messages from this peer. */
    private volatile LinkedList<Long> timestamps;

    /* The input list for this peer */
    private volatile Queue<byte[]> received;

    /* The output buffer for this peer */
    private volatile Queue<byte[]> toSend;

    public Peer(byte[] encoded, byte[] ip) {
        parse(encoded, ip);

        this.timestamps = new LinkedList<>();
        this.received = new LinkedList<>();
        this.toSend = new LinkedList<>();
    }

    public Peer(byte[] version, byte[] address, byte[] port, byte[] privkey) {
        /* If input is IPv4 address, convert to IPv6 mapping */
        if (address.length == 4) address = merge(IPv4inIPv6Prefix, address);

        if (!checkLengths(version, address, port, privkey)) throw new RuntimeException("Invalid input lengths.");

        this.version = version;
        this.address = address;
        this.port = port;
        
        SchnorrKey key = new SchnorrKey(privkey);
        
        this.pubkey = key.getPubkey();
        this.bucketAddr = blake2omit12(pubkey);

        this.timestamps = new LinkedList<>();
        this.received = new LinkedList<>();
        this.toSend = new LinkedList<>();
    }

    public byte[] getEncoded() {
        return CRPENC.encode(version, address, port, pubkey);
    }

    public boolean checkLengths(byte[] version, byte[] address, byte[] port, byte[] privkey) {
        if (version.length != VERSION_LENGTH) return false;
        if (address.length != ADDRESS_LENGTH) return false;
        if (port.length != PORT_LENGTH) return false;
        if (privkey.length != PRIVKEY_LENGTH) return false;

        return true;
    }

    public synchronized void parse(byte[] encoded, byte[] ip) {
        try {
            ENCList decPeer = CRPENC.decode(encoded);

            if (decPeer.size() != 5) throw new RuntimeException("A serialized peer item should have 5 elements.");

            for (ENCItem e : decPeer) {
                if (e.isList()) throw new RuntimeCryptoException("Serialized peer elements should not be lists.");
            }

            if (!checkSer(decPeer)) throw new RuntimeException("Serialized elements are of an incorrect length.");

            this.version = decPeer.get(0).getEncData();
            this.address = decPeer.get(1).getEncData();
            this.port = decPeer.get(2).getEncData();
            this.pubkey = decPeer.get(3).getEncData();

            this.bucketAddr = blake2omit12(pubkey);
            
            SchnorrSig sig = new SchnorrSig(decPeer.get(4).getEncData());

            valid = (SchnorrKey.verify(decPeer.get(4).getEncData(), pubkey, blake2(merge(version, address, port, pubkey))));

            if (valid == false) throw new RuntimeException("The signature on the peer is invalid.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean checkSer(ENCList decPeer) {
        if (decPeer.get(0).getEncData().length != VERSION_LENGTH) return false;
        if (decPeer.get(1).getEncData().length != ADDRESS_LENGTH) return false;
        if (decPeer.get(2).getEncData().length != PORT_LENGTH) return false;
        if (decPeer.get(3).getEncData().length != PUBKEY_LENGTH) return false;
        if (decPeer.get(4).getEncData().length != SIG_LENGTH) return false;

        return true;
    }

    public byte[] getVersion() {
        return version;
    }

    public boolean isIPv4() {
        return (Hex.toHexString(address).startsWith(Hex.toHexString(IPv4inIPv6Prefix)));
    }

    public byte[] getIP() {
        if (isIPv4()) {
            return Arrays.copyOfRange(address, 12, address.length);
        } else {
            return address;
        }
    }

    public byte[] getPort() {
        return port;
    }

    public byte[] getPubkey() {
        return pubkey;
    }

    public byte[] getAddress() {
        return bucketAddr;
    }

    public synchronized void witness() {
        this.time = System.currentTimeMillis();
        this.timestamps.addLast(time);
    }

    public synchronized int getRate() {
        /* Trim away all timestamps over RATE_REF old */
        while (System.currentTimeMillis() - timestamps.getFirst() > (RATE_REF)) {
            timestamps.removeFirst();
        }

        /* Return messages per RATE_REF */
        return timestamps.size();
    }

    public boolean isSpammy() {
        /* If over 1000 messages per minute */
        return (this.getRate() > RATE_REF / 60);
    }

    public boolean isInactive() {
        /* If the peer hasn't been seen in 5 minutes */
        return ((System.currentTimeMillis() - time) > (5 * 60 * 1000));
    }

    public boolean isDead() {
        /* If the peer hasn't been seen in 30 minutes */
        return ((System.currentTimeMillis() - time) > (30 * 60 * 1000));
    }

    public synchronized void send(byte[] message) throws IOException {
        byte[] data = Snappy.compress(message);
        this.toSend.add(semiblobify(data));
    }

    public synchronized byte[] grabForSend() {
        return this.toSend.remove();
    }

    public synchronized void receive(byte[] message) throws IOException {
        byte[] data = deblobify(semideblobify(message));
        byte[] decompressed = Snappy.uncompress(data);

        this.received.add(decompressed);
    }

    public synchronized byte[] grabReceived() {
        return this.received.remove();
    }

    public byte[] toStore() {
        return CRPENC.encode(version, )
    }

    private static ArrayList<byte[]> blobify(byte[] in) {
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

    private static byte[] deblobify(ArrayList<byte[]> in) {
        byte[] temp = new byte[0];

        for (int i = 0; i < in.size(); i++) {
            byte[] current = in.get(i);

            if (current[0] == 0x00) {
                temp = merge(temp, Arrays.copyOfRange(current, 1, 256));
            } else {
                int dist = current[0];
                temp = merge(temp, Arrays.copyOfRange(current, 1, dist + 1));
            }
        }

        return temp;
    }

    private static byte[] semiblobify(byte[] in) {
        ArrayList<byte[]> temp = blobify(in);

        byte[] tempBytes = new byte[0];

        for (int i = 0; i < temp.size(); i++) {
            tempBytes = merge(tempBytes, temp.get(i));
        }

        return tempBytes;
    }

    private static ArrayList<byte[]> semideblobify(byte[] in) {
        byte[][] temp = partition(in, 256);
        ArrayList<byte[]> tempList = new ArrayList<>();

        for (int i = 0; i < temp.length; i++) {
            tempList.add(temp[i]);
        }

        return tempList;
    }

    private static byte[][] partition(byte[] in, int partitionSize) {
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