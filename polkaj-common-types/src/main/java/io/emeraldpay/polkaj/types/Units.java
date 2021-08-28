package io.emeraldpay.polkaj.types;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * List of different units for a DOT amount, each has own name and different amount of decimals
 *
 * @see DotAmount
 * @see DotAmount#Polkadots
 * @see DotAmount#Kusamas
 * @see DotAmount#Westies
 * @see Units.Unit
 */
public class Units {

    public static final Unit Planck = new Unit("Planck", 0);
    public static final Unit Microdot = new Unit("Microdot", "uDOT", 4);
    public static final Unit Millidot = new Unit("Millidot", "mDOT", 7);
    public static final Unit Dot = new Unit("Dot", "DOT", 10);

    public static final Unit Point = new Unit("Point", 3);
    public static final Unit Micrownd = new Unit("Micrownd", "uWND", 6);
    public static final Unit Milliwnd = new Unit("Milliwnd", "mWND", 9);
    public static final Unit Wnd = new Unit("Wnd", "WND", 12);

    private final Unit[] units;

    /**
     * Create a new list of units, the provided list must be sorted by decimals, from smallest to largest
     *
     * @param units units
     */
    public Units(Unit... units) {
        if (units == null) {
            throw new NullPointerException("Units are not provided");
        }
        if (units.length == 0) {
            throw new IllegalArgumentException("Should have at least one unit");
        }
        for (int i = 1; i < units.length; i++) {
            if (units[i].decimals <= units[i-1].decimals) {
                throw new IllegalArgumentException("Units are not ordered by decimal value");
            }
        }
        this.units = units;
    }

    public Unit[] getUnits() {
        return units;
    }

    /**
     * Get the main largest unit from the list.
     *
     * @return main unit
     */
    public Unit getMain() {
        return units[units.length - 1];
    }

    /**
     * Get the base smallest unit from the list.
     * @return base unit
     */
    public Unit getBase() {
        return units[0];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Units)) return false;
        Units units1 = (Units) o;
        return Arrays.equals(units, units1.units);
    }

    @Override
    public int hashCode() {
        return getMain().hashCode();
    }

    public String toString() {
        return getMain().toString();
    }

    /**
     * A single unit, with it's own name and decimals. May have a short name, if exists (i.e., Microdot is the full name, and uDOT is the short name)
     */
    public static class Unit {
        private final int decimals;
        private final String name;
        private final String shortName;

        public Unit(String name, String shortName, int decimals) {
            this.decimals = decimals;
            this.shortName = shortName;
            this.name = name;
        }


        public Unit(String name, int decimals) {
            this(name, name, decimals);
        }

        public int getDecimals() {
            return decimals;
        }

        public String getName() {
            return name;
        }

        public String getShortName() {
            return shortName;
        }

        public BigInteger getMultiplier() {
            return BigInteger.TEN.pow(decimals);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Unit)) return false;
            Unit unit = (Unit) o;
            return decimals == unit.decimals &&
                    name.equals(unit.name) &&
                    Objects.equals(shortName, unit.shortName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(decimals, name);
        }

        public String toString() {
            return name;
        }
    }
}
