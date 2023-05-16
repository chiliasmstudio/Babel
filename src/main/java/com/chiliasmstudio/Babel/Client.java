package com.chiliasmstudio.Babel;

public class Client {
    private static final String SERVER_HOST = "server_host";
    private static final int SERVER_PORT = 8888;
    private static final String TRUSTSTORE_PATH = "/path/to/truststore.jks";
    private static final String TRUSTSTORE_PASSWORD = "truststore_password";

    public static void main(String[] args) {
        try {
            // 載入信任的憑證
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());

            // 初始化 SSL 上下文
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            // 建立 SSLSocket
            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(SERVER_HOST, SERVER_PORT);
            // 僅信任指定的憑證
            socket.setNeedClientAuth(true);

            // 在此處處理與伺服器的連線

            // 關閉連線
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
