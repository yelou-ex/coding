package com.fusepir.database;

/** A non-copying view of D[r + cR][b] as P[c][b](X) coefficients. */
public record BffMatrixLayout(ArithmeticBff bff, int rows, int columns) {
    public BffMatrixLayout {
        if (rows < 1 || columns < 1 || (long) rows * columns < bff.tableLength())
            throw new IllegalArgumentException("matrix does not fit the BFF table");
    }

    public static BffMatrixLayout of(ArithmeticBff bff, CapeParameters parameters) {
        int rows = Math.min(parameters.ringDegreeN(), Math.max(1, (int) Math.ceil(Math.sqrt(bff.tableLength()))));
        int columns = (int) Math.ceil((double) bff.tableLength() / rows);
        return new BffMatrixLayout(bff, rows, columns);
    }

    public int coefficient(int column, int payloadBlock, int row) {
        if (column < 0 || column >= columns || row < 0 || row >= rows || payloadBlock < 0 || payloadBlock >= bff.payloadLength())
            throw new IndexOutOfBoundsException();
        int slot = row + column * rows;
        return slot < bff.tableLength() ? bff.coefficientAt(slot, payloadBlock) : 0;
    }

    public int[] reconstructSlot(int slot) {
        if (slot < 0 || slot >= bff.tableLength()) throw new IndexOutOfBoundsException(slot);
        int row = slot % rows;
        int column = slot / rows;
        int[] entry = new int[bff.payloadLength()];
        for (int block = 0; block < entry.length; block++) entry[block] = coefficient(column, block, row);
        return entry;
    }
}
