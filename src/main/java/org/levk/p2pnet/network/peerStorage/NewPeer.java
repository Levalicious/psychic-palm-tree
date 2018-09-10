package org.levk.p2pnet.network.peerStorage;

import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.util.encoders.Hex;

public class NewPeer {
    public final static byte[] IPv4inIPv6Prefix = Hex.decode("00000000000000000000FFFF");

    public final static int NETWORK_LENGTH = 2;
    public final static int VERSION_LENGTH = 3;
    public final static int ADDRESS_LENGTH = 16;
    public final static int PORT_LENGTH = 2;

    /* Number of milliseconds to observe the number of 
     * messages during. Currently an hour. */
    public final static int RATE_REF = 1 * 60 * 60 * 1000;

    /* When this peer last sent a valid message.
     * more "active" peers are prioritized. */
    private long time;

    /* The ID of the network this node operates
     * on. */
    private byte[] networkId;

    /* The client version that this peer is running */
    private byte[] version;

    /* The network address of this node. If IPv4,
     * it's an IPv4-mapped IPv6 address. Otherwise,
     * it's a plain IPv6 one */
    private byte[] address;

    /* The port upon which this node listens for
     * new connections */
    private byte[] port;

    /* The timestamps for the N most recently witnessed 
     * messages from this peer. */
    private volatile LinkedList<Long> timestamps;

    /* The input list for this peer */
    private volatile Queue<byte[]> received;

    /* The output buffer for this peer */
    private volatile Queue<byte[]> toSend;

    public NewPeer(byte[] encoded, byte[] ip) {
        parse(encoded ,ip);

        this.timestamps = new LinkedList<>();
        this.received = new LinkedList<>();
        this.toSend = new LinkedList<>();
    }

    public NewPeer(byte[] networkId, byte[] version, byte[] address, byte[] port) {
        /* If input address is IPv4, map to IPv6 */
        if (address.length == 4) address = merge(IPv4inIPv6Prefix, address)
    }

}