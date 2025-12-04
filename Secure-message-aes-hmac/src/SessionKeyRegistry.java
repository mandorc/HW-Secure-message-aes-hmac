/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author armando
 */
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class SessionKeyRegistry {

    private static final SessionKeyRegistry INSTANCE = new SessionKeyRegistry();

    public static SessionKeyRegistry get() {
        return INSTANCE;
    }

    private final ConcurrentMap<String, CryptoKit.Keys> map = new ConcurrentHashMap<>();

    private SessionKeyRegistry() {}

    private String key(String a, String b) {
        String x = a.toLowerCase();
        String y = b.toLowerCase();
        return (x.compareTo(y) <= 0) ? x + "|" + y : y + "|" + x;
    }

    public void put(String a, String b, CryptoKit.Keys keys) {
        map.put(key(a, b), keys);
    }

    public CryptoKit.Keys getKeys(String a, String b) {
        return map.get(key(a, b));
    }

    public void clearFor(String a, String b) {
        map.remove(key(a, b));
    }
}