package com.bsharan.auth_service.utils;

import java.util.UUID;

public class Utils {
    public static UUID parseUUID(String uuid){
        return UUID.fromString(uuid);
    }
}
