package com.chiliasmstudio.Babel.server;

public class ServerMain {
    public static void main(String[] args) throws Exception {
        SocketServer socketServer = new SocketServer();
        socketServer.start();
    }
}
