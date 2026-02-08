package eu.starsong.ghidra.model;

/**
 * Immutable model class that pre-computes expensive values from Ghidra's Data objects
 * for string entries. Used by StringCacheManager to avoid repeated costly calls to
 * getDefaultValueRepresentation() and getPrimarySymbol() on every request.
 */
public final class StringInfo {
    private final String address;
    private final String value;
    private final String valueLower;
    private final int length;
    private final String typeName;
    private final String symbolName;

    public StringInfo(String address, String value, int length, String typeName, String symbolName) {
        this.address = address;
        this.value = value != null ? value : "";
        this.valueLower = this.value.toLowerCase();
        this.length = length;
        this.typeName = typeName != null ? typeName : "";
        this.symbolName = symbolName != null ? symbolName : "";
    }

    public String getAddress() {
        return address;
    }

    public String getValue() {
        return value;
    }

    public String getValueLower() {
        return valueLower;
    }

    public int getLength() {
        return length;
    }

    public String getTypeName() {
        return typeName;
    }

    public String getSymbolName() {
        return symbolName;
    }
}
