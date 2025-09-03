
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author arman
 */
public class ClientRegistry {

    private static final ClientRegistry INSTANCE = new ClientRegistry();
    private final java.util.concurrent.ConcurrentMap<String, FrameClient> clients = new java.util.concurrent.ConcurrentHashMap<>();
    private ClientRegistry() {}
    public static ClientRegistry get() { return INSTANCE; }

    public boolean register(String id, FrameClient frame) {
        String key = id.toLowerCase();
        return clients.putIfAbsent(key, frame) == null;
    }
    public void unregister(String id) {
        clients.remove(id.toLowerCase());
    }
    public boolean exists(String id) {
        return clients.containsKey(id.toLowerCase());
    }
    public FrameClient get(String id) {
        return clients.get(id.toLowerCase());
    }
}
