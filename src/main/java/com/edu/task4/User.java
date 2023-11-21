package com.edu.task4;

import jakarta.persistence.*;

@Entity
@Table(name = "[user]")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private int id;

    @Column(name = "[login]", length = 50, unique = true, nullable = false)
    private String login;

    @Column(name = "salt", length = 32, unique = true, nullable = false)
    private byte[] salt;

    @Column(name = "salt_password", length = 32, nullable = false)
    private byte[] saltPassword;

    public User() {
    }

    public User(String login, byte[] salt, byte[] saltPassword) {
        this.login = login;
        this.salt = salt;
        this.saltPassword = saltPassword;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public void setSaltPassword(byte[] saltPassword) {
        this.saltPassword = saltPassword;
    }

    public int getId() {
        return id;
    }

    public String getLogin() {
        return login;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getSaltPassword() {
        return saltPassword;
    }
}
