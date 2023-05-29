package com.chiliasmstudio.Babel.server;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class test {
    public static void main(String[] args) {
        int serverPort = 65535;

        try {
            SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(serverPort);

            // 设置仅信任特定证书
            sslServerSocket.setSSLParameters(sslServerSocket.getSSLParameters());

            System.out.println("Server listening on port " + serverPort);

            Socket clientSocket = sslServerSocket.accept();

            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // 从客户端接收数据
            String clientMessage = in.readLine();
            System.out.println("Received from client: " + clientMessage);

            // 发送响应给客户端
            out.println("Hello, client!");

            // 关闭连接
            out.close();
            in.close();
            clientSocket.close();
            sslServerSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
