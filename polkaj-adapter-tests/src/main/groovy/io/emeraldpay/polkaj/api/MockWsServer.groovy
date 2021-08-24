package io.emeraldpay.polkaj.api

import org.java_websocket.WebSocket
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.server.WebSocketServer

import java.nio.ByteBuffer

class MockWsServer extends WebSocketServer {

    List<ReceivedMessage> received = []
    private WebSocket conn

    private String next

    MockWsServer(int port) {
        super(new InetSocketAddress("127.0.0.1", port))
    }

    void reply(String message) {
        println("MOCKWS: >> $message")
        if (conn == null) {
            println("MOCKWS: ERROR, no active connection")
        }
        conn.send(message)
    }

    void onNextReply(String message) {
        next = message
    }

    @Override
    void onOpen(WebSocket conn, ClientHandshake handshake) {
        this.conn = conn
        println("MOCKWS: Opened connection from ${conn.remoteSocketAddress}")
    }

    @Override
    void onClose(WebSocket conn, int code, String reason, boolean remote) {
        this.conn = null
        println("MOCKWS: Connection closed, code ${code} with msg '${reason}' ${remote ? 'by remote' : 'by server'}")
    }

    @Override
    void onMessage(WebSocket conn, String message) {
        println("MOCKWS: << $message")
        received.add(new ReceivedMessage(message))
        if (next != null) {
            reply(next)
            next = null
        }
    }

    @Override
    void onMessage(WebSocket conn, ByteBuffer message) {
        println("MOCKWS: bytes msg")
        super.onMessage(conn, message)
    }


    @Override
    void onError(WebSocket conn, Exception ex) {
        println("MOCKWS: ERROR, $ex.message")
        received.add(new ReceivedMessage("Err: ${ex.message}"))
    }

    @Override
    void onStart() {
        println("MOCKWS: Server started")
    }

    class ReceivedMessage {
        String value

        ReceivedMessage(String value) {
            this.value = value
        }
    }

}
