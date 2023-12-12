package com.chiliasmstudio.Babel.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ClientMain {

    public static void main(String[] args) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String ipAddress = "";
        while (true) {
            System.out.print("Enter ip address:");
            ipAddress = reader.readLine();
            if (!ipAddress.isEmpty())
                break;
        }

        String userName = "";
        while (true) {
            System.out.print("Enter username:");
            userName = reader.readLine();
            if (!userName.isEmpty())
                break;
        }

        SocketClient socketClient = new SocketClient(userName,ipAddress);
        synchronized (socketClient) {
            socketClient.start();
            socketClient.wait();
            while (true) {
                String line = reader.readLine();
                socketClient.SendMessage(line);
            }
        }

    }
}
