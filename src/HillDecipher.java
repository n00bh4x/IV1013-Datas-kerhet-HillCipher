import org.jscience.mathematics.number.LargeInteger;
import org.jscience.mathematics.number.Rational;
import org.jscience.mathematics.vector.DenseMatrix;
import org.jscience.mathematics.vector.DenseVector;
import org.jscience.mathematics.vector.DimensionException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;

/**
 * Created by mikaelnorberg on 2017-03-31.
 *
 * Klassen läser in ett krypterat meddelande från en fil och en nyckel från en fil och dekrypterar meddelandet med
 * nyckeln. det dekrypterade meddelandet skrivs till en annan angiven fil.
 */
public class HillDecipher {

    private final DenseMatrix<Rational> cipherText;
    private final DenseMatrix<Rational> key;
    private final DenseMatrix<Rational> plainText;

    /**
     * @param radix modulovärdet
     * @param blockSize storleken på ett block
     * @param keyFile filen med nyckeln
     * @param plainFile filen att skriva den dekrypterade texten till
     * @param cipherFile filen med texten som ska dekrypteras
     */
    public HillDecipher(int radix, int blockSize, String keyFile, String plainFile, String cipherFile) {
        byte[] cipherText = cipherTextBlockSequence(cipherFile);
        this.cipherText = getCipherTextMatrix(cipherText, blockSize, radix);
        this.key = getKeyFrom(keyFile);
        this.plainText = decryptCipher(radix);
        int padding = removePadding(blockSize);
        writePlainToFile(padding, plainFile);
    }

    private int removePadding(int blockSize) {
        DenseVector<Rational> column = this.plainText.getColumn(this.plainText.getNumberOfColumns()-1);
        final int SIZE = column.getDimension();
        long padding = column.get(SIZE-1).getDividend().longValue();
        if(padding > blockSize){
            System.out.println();
            System.out.println("OBS! Innehållet i cipherfilen");
            System.out.println("krypterades ej med dekrypteringsnyckelns invers.");
            System.out.println();
        }
        int paddingCounter = 1;
        for(int i = SIZE-2; i >= 0; i--){
            if(column.get(i).getDividend().compareTo(padding) == 0){
                paddingCounter++;
            } else {
                break;
            }
        }
        return paddingCounter;
    }



    private DenseMatrix<Rational> decryptCipher(int radix){
        final int COLUMNS = this.cipherText.getNumberOfColumns();
        @SuppressWarnings("unchecked")
        DenseVector<Rational>[] columns = new DenseVector[COLUMNS];
        for (int i = 0; i < COLUMNS; i++){
            columns[i] = decrypt(radix, this.cipherText.getColumn(i));
        }
        return collect(columns);
    }


    private DenseMatrix<Rational> collect(DenseVector<Rational>[] allColumns){
        Rational[][] matrix = new Rational[this.cipherText.getNumberOfRows()][this.cipherText.getNumberOfColumns()];
        for(int i = 0; i < allColumns.length; i++){
            for(int j = 0; j < allColumns[i].getDimension(); j++){
                matrix[j][i] = allColumns[i].get(j);
            }
        }
        return DenseMatrix.valueOf(matrix);
    }


    private DenseVector<Rational> decrypt(int radix, DenseVector<Rational> column){
        Rational[] tempVector = null;
        try{
            DenseVector<Rational> cipherKeyProduct = this.key.times(column);

            final int DIMENSIONS = cipherKeyProduct.getDimension();
            tempVector = new Rational[DIMENSIONS];

            for(int i = 0; i < DIMENSIONS; i++){
                tempVector[i] = Rational.valueOf(cipherKeyProduct.get(i).getDividend().mod(LargeInteger.valueOf(radix)),
                        LargeInteger.ONE);
            }
        } catch (DimensionException e) {
            System.out.println("Nyckeln måste ha dimensionen nxn och blockstorleken måste vara nx1");
            System.out.println("Försök igen.");
            System.out.println();
            System.out.println("Dekryptering avbryts. Programmet avslutas");
            System.exit(0);
        }
        return DenseVector.valueOf(tempVector);
    }



    private void writePlainToFile(int padding, String plainFile) {
        final int ROWS = this.plainText.getNumberOfRows();
        final int COLUMNS = this.plainText.getNumberOfColumns();
        final int SIZE = COLUMNS * ROWS - padding;
        final byte[] PLAIN = new byte[SIZE];
        int index = 0;
        for (int i = 0; i < COLUMNS; i++) {
            for (int j = 0; j < ROWS; j++) {
                if (index >= PLAIN.length) {
                    break;
                } else {
                    PLAIN[index++] = this.plainText.get(j, i).getDividend().byteValue();
                }
            }
        }
        try (FileOutputStream fos = new FileOutputStream(plainFile)){
            DataOutputStream output = new DataOutputStream(fos);
            output.write(PLAIN);
            output.close();
        } catch (FileNotFoundException e) {
            System.out.println("Kontrollera skrivrättigheter för " + plainFile + " och försök igen.");
            System.out.println("Dekryptering avbruten. Programmet avslutas.");
            System.exit(0);
        } catch (IOException f) {
            System.out.println("Något gick fel när data skrevs till " + plainFile);
            System.out.println("Dekryptering avbruten. Programmet avslutas.");
            System.exit(0);
        }
    }


    private DenseMatrix<Rational> getKeyFrom(String keyFile) {
        String key = null;
        try {
            key = new String(Files.readAllBytes(Paths.get(keyFile)));
        } catch (OutOfMemoryError e){
            System.out.println("Inte tillräckligt med minne.");
            System.out.println("Försök igen.");
            System.out.println();
            System.out.println("Deryptering avbryts. Programmet avslutas");
            System.exit(0);
        } catch (SecurityException e) {
            System.out.println("Kontrollera filens läsrättigheter och försök igen.");
            System.out.println();
            System.out.println("Deryptering avbryts. Programmet avslutas");
            System.exit(0);
        } catch (InvalidPathException e) {
            System.out.println("Filens sökväg är felaktig.");
            System.out.println();
            System.out.println("Deryptering avbryts. Programmet avslutas");
            System.exit(0);
        } catch (IOException e) {
            System.out.println("Något gick fel när filen " + keyFile + " lästes");
            System.out.println("kontrollera att filen existerar och försök igen.");
            System.out.println();
            System.out.println("Deryptering avbryts. Programmet avslutas");
            System.exit(0);
        }
        return createKeyMatrix(key);
    }

    private DenseMatrix<Rational> createKeyMatrix(String key) {
        final int COLUMNS;
        final int ROWS;
        Rational[][] keyMatrix;
        int index = 0;
        String[] keyValues = key.split("\\s+");
        COLUMNS = (int) Math.sqrt((double) keyValues.length);
        if(COLUMNS*COLUMNS != keyValues.length){
            System.out.println("Nyckeln måste vara en nxn matris med n > 1");
            System.out.println();
            System.out.println("Dekryptering avbruten. Programmet avslutas");
            System.exit(0);
        }
        ROWS = COLUMNS;
        keyMatrix = new Rational[ROWS][COLUMNS];
        for (int i = 0; i < ROWS; i++) {
            for (int j = 0; j < COLUMNS; j++) {
                try{
                    keyMatrix[i][j] = Rational.valueOf(keyValues[index++]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    System.out.println("Endast positiva heltal är tillåtna i nyckeln.");
                    System.out.println("Nyckeln innehöll: " + keyValues[index-1]);
                    System.out.println("Dekryptering avbruten. Programmet avslutas.");
                    System.exit(0);
                }
            }
        }
        DenseMatrix<Rational> theKey = DenseMatrix.valueOf(keyMatrix);
        if((theKey.getNumberOfColumns() < 2) && (theKey.getNumberOfRows() < 2)){
            System.out.println("Nyckeln måste vara en nxn matris med n > 1");
            System.out.println();
            System.out.println("Dekryptering avbruten. Programmet avslutas");
            System.exit(0);
        }
        return theKey;
    }


    private DenseMatrix<Rational> getCipherTextMatrix(byte[] cipherText, int blockSize, int radix) {
        if(cipherText.length % blockSize != 0){
            System.out.println("Det här meddelandet krypterades inte med dekrypteringsnyckelns invers.");
            System.out.println("Dekryptering avbryts. Programmet avslutas");
            System.exit(0);
        }
        Rational[][] plainMatrix = new Rational[blockSize][cipherText.length/blockSize];
        final int ROWS = blockSize;
        final int COLUMNS = cipherText.length/blockSize;
        int offset = 0;
        LargeInteger value;
        for (int i = 0; i < COLUMNS; i++){
            for (int j = 0; j < ROWS; j++){
                value = LargeInteger.valueOf(cipherText, offset++, 1);
                if(value.isNegative()){
                    value = LargeInteger.valueOf(value.longValue() & 0xFF);
                }
                if(radix <= value.longValue()){
                    System.out.println("All input måste ha ett värde som är mindre än radix.");
                    System.out.println("Dekryptering avbruten. programmet avslutas");
                    System.exit(0);
                }
                plainMatrix[j][i] = Rational.valueOf(value, LargeInteger.ONE);
            }
        }
        return DenseMatrix.valueOf(plainMatrix);
    }

    private byte[] cipherTextBlockSequence(String fileName){
        byte[] plainText = null;
        try (FileInputStream fis = new FileInputStream(fileName)){
            final int FILESIZE = (int) fis.getChannel().size();
            if(FILESIZE == 0){
                System.out.println("Filen innehåller ingen data att dekryptera.");
                System.out.println();
                System.out.println("Dekryptering avbruten. programmet avslutas");
                System.exit(0);
            }
            plainText = new byte[FILESIZE];
            DataInputStream input  = new DataInputStream(fis);
            for(int i = 0; i < plainText.length; i++) {
                plainText[i] = input.readByte();
            }
        } catch (FileNotFoundException e) {
            System.out.println("Filen " + fileName + " gick inte att öppna.");
            System.out.println("Kontrollera att filen finns och försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        } catch (EOFException e) {
            System.out.println("Något gick fel vid läsning av " + fileName + ". Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }catch (IOException e) {
            System.out.println("Något gick fel med filen " + fileName + ". Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }
        return plainText;
    }




    public static void main(String[] args){

        System.out.println("HILLDECIPHER");
        if(args.length != 5) {
            System.out.println("Fel antal argument.");
            System.out.println("mata in: <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
            System.out.println("Dekryptering avbruten försök igen");
        }  else {
            int radix;
            int blockSize;
            String keyFile = args[2];
            String plainFile = args[3];
            String cipherFile = args[4];
            try {
                radix = Integer.parseInt(args[0]);
                try {
                    blockSize = Integer.parseInt(args[1]);
                    if (radix < 2 || radix > 256) {
                        System.out.println("Argumentet <radix> måste uppfylla: 2 <= radix <= 256");
                        System.out.println("Programmet anropades med <radix> = " + args[0]);
                        System.out.println("Dekryptering avbruten försök igen");
                    } else if(blockSize < 2 || blockSize > 8) {
                        System.out.println("Argumentet <blocksize> måste uppfylla: 2 <= blocksize <= 8");
                        System.out.println("Programmet anropades med <blocksize> = " + args[1]);
                        System.out.println("Dekryptering avbruten försök igen");
                    } else {
                        new HillDecipher(radix, blockSize, keyFile, plainFile, cipherFile);
                        System.out.println("Dekryptering genomförd");
                    }

                } catch (NumberFormatException e) {
                    System.out.println("Endast heltal 2-8 är tillåtna");
                    System.out.println("Programmet anropades med <blocksize> = " + args[1]);
                    System.out.println("Dekryptering avbruten försök igen");
                }
            } catch (NumberFormatException e) {
                System.out.println("Endast heltal 2-256 är tillåtna");
                System.out.println("Programmet anropades med <radix> = " + args[0]);
                System.out.println("Dekryptering avbruten försök igen");
            }
        }
        System.out.println("Programmet avslutas");
    }
}


