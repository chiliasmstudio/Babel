package com.chiliasmstudio.Babel.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ClientMain {
    public static void main(String[] args) throws Exception{
        SocketClient socketClient = new SocketClient();
        socketClient.start();
        socketClient.wait();
        while (true){
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Send:");
            String line = reader.readLine();
            socketClient.SendMessage(line);
        }
    }
}
