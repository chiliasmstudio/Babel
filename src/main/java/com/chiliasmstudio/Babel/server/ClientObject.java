package com.chiliasmstudio.Babel.server;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import javax.net.ssl.SSLSocket;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.UUID;

public class ClientObject {
    public ClientObject(String name, SSLSocket socket, PrintWriter printWriter) {
        this.name = name;
        this.Printer = printWriter;
        this.Socket = socket;
    }

    /**
     * Return Unique ID of client.
     */
    @Getter(AccessLevel.PUBLIC) private String name;

    //@Getter(AccessLevel.PUBLIC) private UUID ProxyUUID;

    /**
     * Return Socket(SSLSocket) of client.
     */
    @Getter(AccessLevel.PUBLIC) private SSLSocket Socket;

    /**
     * Return Printer of client.
     */
    @Getter(AccessLevel.PUBLIC) private PrintWriter Printer;
}
