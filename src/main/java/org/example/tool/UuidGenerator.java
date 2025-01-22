package org.example.tool;


import java.util.UUID;

public class UuidGenerator {

    private int version;

    public UuidGenerator(){
        this.version = 1;
    }

    public UuidGenerator(int version){
        this.version = version;
    }

    public UUID generate(){
        UUID uuid ;
        return UUID.randomUUID();

    }

    public String generateUuidString(){
        UUID uuid = generate();
        return uuid.toString().replaceAll("-", "");
    }


}
