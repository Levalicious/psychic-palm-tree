package org.levk.p2pnet.network.peerStorage;

public class PeerStorage {
    private static volatile int peerCount;
    private final int k;
    private volatile Bucket[] buckets;
    private final byte[] nodeAddress;

    public PeerStorage(int k, byte[] address) {
        this.k = k;
        this.nodeAddress = address;
    }

    private class Bucket {
        private byte[] zero = {(byte) 0x00};
        private Peer[] peers;
        private int k;

        Bucket(int k) {
            this.k = k;
            this.peers = new Peer[k];
        }

        public void broadcast(int messagetype, byte[] message) {
            for (int i = 0; i < k; i++) {
                if (peers[i] != null) {
                    //peers[i].send(messagetype, message);
                }
            }
        }

    }
}