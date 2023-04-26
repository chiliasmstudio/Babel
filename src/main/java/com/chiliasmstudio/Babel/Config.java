package com.chiliasmstudio.Babel;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;

public class Config {
    /**
     * Load config value form config.properties.
     *
     * @param configFileDir Directory of config.
     * @throws IOException When fail to load config.
     * @throws Exception   When required argument is invalid.
     */
    public static void LoadConfig(String configFileDir) throws Exception {
        Properties properties = new Properties();
        if (configFileDir == null || configFileDir.isEmpty())
            configFileDir = "config/config.properties";
        try {
            properties.load(new FileInputStream(configFileDir));
        } catch (IOException ex) {
            throw new IOException("Fail to load config file!");
        }

        DiscordToken = properties.getProperty("DiscordToken", "");
        if (DiscordToken == null || DiscordToken.isEmpty())
            throw new Exception("Discord Token not found!");

        SteamKey = properties.getProperty("SteamKey", "");
        if (SteamKey == null || SteamKey.isEmpty())
            throw new Exception("SteamKey not found!");

        String ServersLine = properties.getProperty("Servers", "");
        Servers.addAll(Arrays.asList(ServersLine.split(";")));
        if (Servers == null || Servers.isEmpty())
            throw new Exception("Servers not found!");


    }

    /**
     * Token of discord bot.
     */
    public static String DiscordToken = "";

    /**
     * Steam Web API key.
     */
    public static String SteamKey = "";

    /**
     * Servers to manage.
     */
    public static ArrayList<String> Servers = new ArrayList<>();

}
