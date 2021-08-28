package io.emeraldpay.polkaj.scaletypes;

import java.util.Objects;

public class AccountInfo {

    private Long nonce;
    private Long consumers;
    private Long providers;
    private Long sufficients;
    private AccountData data;

    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
    }

    public Long getConsumers() {
        return consumers;
    }

    public void setConsumers(Long consumers) {
        this.consumers = consumers;
    }

    public Long getProviders() {
        return providers;
    }

    public void setProviders(Long providers) {
        this.providers = providers;
    }

    public Long getSufficients() {
        return sufficients;
    }

    public void setSufficients(Long sufficients) {
        this.sufficients = sufficients;
    }

    public AccountData getData() {
        return data;
    }

    public void setData(AccountData data) {
        this.data = data;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AccountInfo)) return false;
        AccountInfo that = (AccountInfo) o;
        return Objects.equals(nonce, that.nonce) &&
                Objects.equals(consumers, that.consumers) &&
                Objects.equals(providers, that.providers) &&
                Objects.equals(sufficients, that.sufficients) &&
                Objects.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(nonce, consumers, providers, sufficients, data);
    }

    @Override
    public String toString() {
        return "AccountInfo{" +
                "nonce=" + nonce +
                ", consumers=" + consumers +
                ", providers=" + providers +
                ", sufficients=" + sufficients +
                ", data=" + data +
                '}';
    }
}
