package io.emeraldpay.polkaj.types;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.util.Objects;

import io.emeraldpay.polkaj.ss58.SS58Type;
import io.emeraldpay.polkaj.types.Units.Unit;

/**
 * Amount value, in DOTs
 *
 * @see <a href="https://wiki.polkadot.network/docs/en/learn-DOT">https://wiki.polkadot.network/docs/en/learn-DOT</a>
 */
public class DotAmount implements Comparable<DotAmount>{

    /**
     * Standard units for DOT token
     *
     * Planck -&gt; Microdot -&gt; Millidot -&gt; Dot
     */
    public static final Units Polkadots = new Units(
            Units.Planck,
            Units.Microdot,
            Units.Millidot,
            Units.Dot
    );

    /**
     * Kusama units
     *
     * Planck -&gt;  Point -&gt; MicroKSM -&gt; MilliKSM -&gt; KSM
     */
    public static final Units Kusamas = new Units(
            new Unit("Planck", 0),
            new Unit("Point", 3),
            new Unit("MicroKSM", "uKSM", 6),
            new Unit("MilliKSM", "mKSM", 9),
            new Unit("KSM", 12)
    );
    
    /**
     * Westend testnet units
     *
     * Planck -&gt;  Point -&gt; MicroWND -&gt; MilliWND -&gt; WND
     */
    public static final Units Westies = new Units(
            Units.Planck,
            Units.Point,
            Units.Micrownd,
            Units.Milliwnd,
            Units.Wnd
    );

    /**
     * Zero Dots
     */
    public static final DotAmount ZERO = new DotAmount(BigInteger.ZERO);

    private static final Unit DOT_UNIT = Polkadots.getMain();
    private static final BigInteger DOT_MULTIPLIER = DOT_UNIT.getMultiplier();
    private static final BigDecimal DOT_MULTIPLIER_DECIMAL = new BigDecimal(DOT_MULTIPLIER);

    private final BigInteger value;
    private final Units units;

    /**
     * Create a standard DOT amount for the specified amount
     *
     * @param value amount
     */
    public DotAmount(BigInteger value) {
        this(value, Polkadots);
    }

    /**
     * Create a DOT amount with custom units
     *
     * @see DotAmount#Polkadots
     * @see DotAmount#Kusamas
     * @see DotAmount#Westies
     *
     * @param value amount
     * @param units custom units
     */
    public DotAmount(BigInteger value, Units units) {
        this.value = value;
        this.units = units;
    }

    /**
     * Create a DOT amount for a specific network
     *
     * @see DotAmount#Polkadots
     * @see DotAmount#Kusamas
     * @see DotAmount#Westies
     *
     * @param value amount
     * @param network the network to determine the custom units for
     */
    public DotAmount(BigInteger value, SS58Type.Network network) {
        this(value, getUnitsForNetwork(network));
    }

    public static DotAmount fromPlancks(long amount) {
        return new DotAmount(BigInteger.valueOf(amount), Polkadots);
    }

    public static DotAmount fromPlancks(long amount, Units units) {
        return new DotAmount(BigInteger.valueOf(amount), units);
    }

    public static DotAmount fromPlancks(String amount) {
        return new DotAmount(new BigInteger(amount), Polkadots);
    }

    public static DotAmount fromDots(long amount) {
        return new DotAmount(
                BigInteger.valueOf(amount).multiply(DOT_MULTIPLIER),
                Polkadots);
    }

    public static DotAmount fromDots(double amount) {
        return new DotAmount(
                BigDecimal.valueOf(amount).multiply(DOT_MULTIPLIER_DECIMAL).toBigInteger(),
                Polkadots);
    }

    public static DotAmount from(long amount, Units units) {
        BigInteger unitMultiplier = units.getMain().getMultiplier();
        return new DotAmount(
                BigInteger.valueOf(amount).multiply(unitMultiplier),
                units);
    }

    public static DotAmount from(double amount, Units units) {
        BigDecimal unitMultiplierDecimal = new BigDecimal(units.getMain().getMultiplier());
        return new DotAmount(
                BigDecimal.valueOf(amount).multiply(unitMultiplierDecimal).toBigInteger(),
                units);
    }

    public boolean isSame(DotAmount another) {
        return units.equals(another.units);
    }

    protected void requireSame(DotAmount another) {
        if (!isSame(another)) {
            throw new IllegalStateException("Amounts belong to different networks");
        }
    }

    public DotAmount add(DotAmount amount) {
        requireSame(amount);
        return new DotAmount(this.value.add(amount.value), this.units);
    }

    public DotAmount subtract(DotAmount amount) {
        requireSame(amount);
        return new DotAmount(this.value.subtract(amount.value), this.units);
    }

    public DotAmount multiply(long n) {
        return new DotAmount(this.value.multiply(BigInteger.valueOf(n)), this.units);
    }

    public DotAmount divide(long n) {
        return new DotAmount(this.value.divide(BigInteger.valueOf(n)), this.units);
    }

    public BigInteger getValue() {
        return value;
    }

    public BigDecimal getValue(Unit unit) {
        if (unit.getDecimals() == 0) {
            return new BigDecimal(value);
        }
        return new BigDecimal(value)
                .divide(new BigDecimal(unit.getMultiplier()), MathContext.DECIMAL64);
    }

    public Units getUnits() {
        return units;
    }

    /**
     * Finds a minimal unit for which a value represented in that unit has a whole part.
     * For example for 0.100 Dots the unit is Millidot (100 Millidots), for 0.000075 it's Microdot (75 Microdots), and so on.
     *
     * @return a minimal unit
     */
    public Unit getMinimalUnit() {
        return getMinimalUnit(getUnits().getUnits()[0]);
    }

    /**
     * Finds a minimal unit, down to specified limit, for which a value represented in that unit has a whole part.
     * For example for 0.100 Dots the unit is Millidot (100 Millidots), for 0.000075 it's Microdot (75 Microdots), and so on.
     *
     * @param limit the limit that stop further decrease of the unit
     * @return a minimal unit
     */
    public Unit getMinimalUnit(Unit limit) {
        Unit[] units = getUnits().getUnits();
        for (int i = units.length-1; i > 0; i--) {
            Unit unit = units[i];
            if (unit == limit) {
                return unit;
            }
            if (value.compareTo(unit.getMultiplier()) >= 0) {
                return unit;
            }
        }
        return units[0];
    }

    /**
     * <p>Retrieve the {@link Units} matching the given network.</p>
     * <p>{@link #Polkadots} is used as default if the no units have been defined for the network.</p>
     *
     * @param network the SS58 network type for which to get the units
     * @return units for the given network
     */
    public static Units getUnitsForNetwork(SS58Type.Network network) {
        if (SS58Type.Network.CANARY.equals(network)) {
            return Kusamas;
        }
        if (SS58Type.Network.SUBSTRATE.equals(network)) {
            return Westies;
        }
        return Polkadots;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DotAmount)) return false;
        DotAmount dotAmount = (DotAmount) o;
        return value.equals(dotAmount.value) &&
                units.equals(dotAmount.units);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value, units);
    }

    @Override
    public String toString() {
        return value.toString() + " " + units.getMain().getShortName();
    }

    @Override
    public int compareTo(DotAmount o) {
        if (units != o.units) {
            return units.getMain().getName().compareTo(o.units.getMain().toString());
        }
        return value.compareTo(o.value);
    }
}
