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
 * Klassen läser in ett meddelande från en fil och en nyckel från en fil och krypterar meddelandet med
 * nyckeln. det krypterade meddelandet skrivs till en annan angiven fil.
 */
public class SmsCipher {


    private final DenseMatrix<Rational> plainText;
    private final DenseMatrix<Rational> key;
    private final DenseMatrix<Rational> cipher;

    /**
     *
     * @param radix modulovärdet
     * @param blockSize storleken på ett block
     * @param keyFile filen med nyckeln
     * @param plainFile filen med texten som ska krypteras
     * @param cipherFile filen att skriva den krypterade texten till
     */
    public SmsCipher(int radix, int blockSize, String keyFile, String plainFile, String cipherFile) {

        byte[] plainText = plainTextBlockSequence(blockSize, plainFile);
        this.plainText = getPlainTextMatrix(plainText, blockSize);
        this.key = getKeyFrom(keyFile);
        this.cipher = encryptPlain(radix);
        writeCipherToFile(cipherFile);
    }


    private void writeCipherToFile(String cipherFile) {

        final int ROWS = this.cipher.getNumberOfRows();
        final int COLUMNS = this.cipher.getNumberOfColumns();
        final byte[] CIPHER = new byte[COLUMNS * ROWS];
        int index = 0;
        for (int i = 0; i < COLUMNS; i++) {
            for (int j = 0; j < ROWS; j++) {
                CIPHER[index++] = this.cipher.get(j, i).getDividend().plus(65).byteValue();
            }
        }
        try (FileOutputStream fos = new FileOutputStream(cipherFile)){
            DataOutputStream output = new DataOutputStream(fos);
            output.write(CIPHER);
            output.close();
        } catch (FileNotFoundException e) {
            System.out.print("Kontrollera skrivrättigheter för " + cipherFile + " och försök igen.");
            System.out.println("Kryptering avbruten. Programmet avslutas.");
            System.exit(0);
        } catch (IOException f) {
            System.out.println("Något gick fel när data skrevs till " + cipherFile);
            System.out.println("Kryptering avbruten. Programmet avslutas.");
            System.exit(0);
        }
    }

    private DenseMatrix<Rational> encryptPlain(int radix){
        final int COLUMNS = this.plainText.getNumberOfColumns();
        @SuppressWarnings("unchecked")
        DenseVector<Rational>[] columns = new DenseVector[COLUMNS];
        for (int i = 0; i < COLUMNS; i++){
            columns[i] = encrypt(radix, this.plainText.getColumn(i));
        }
        return collect(columns);
    }


    private DenseMatrix<Rational> collect(DenseVector<Rational>[] allColumns){
        Rational[][] matrix = new Rational[this.plainText.getNumberOfRows()][this.plainText.getNumberOfColumns()];
        for(int i = 0; i < allColumns.length; i++){
            for(int j = 0; j < allColumns[i].getDimension(); j++){
                matrix[j][i] = allColumns[i].get(j);
            }
        }
        return DenseMatrix.valueOf(matrix);
    }


    private DenseVector<Rational> encrypt(int radix, DenseVector<Rational> column){
        Rational[] tempVector = null;
        try{
            DenseVector<Rational> plainKeyProduct = this.key.times(column);

            final int DIMENSIONS = plainKeyProduct.getDimension();
            tempVector = new Rational[DIMENSIONS];

            for(int i = 0; i < DIMENSIONS; i++){
                tempVector[i] = Rational.valueOf(plainKeyProduct.get(i).getDividend().mod(LargeInteger.valueOf(radix)),
                        LargeInteger.ONE);
            }
        } catch (DimensionException e) {
            System.out.println("Nyckeln måste ha dimensionen nxn och blockstorleken måste vara nx1");
            System.out.println("Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }
        return DenseVector.valueOf(tempVector);
    }


    private DenseMatrix<Rational> getKeyFrom(String keyFile) {
        String key = null;
        try {
            key = new String(Files.readAllBytes(Paths.get(keyFile)));
            } catch (OutOfMemoryError e){
                System.out.println("Inte tillräckligt med minne.");
                System.out.println("Försök igen.");
                System.out.println();
                System.out.println("Programmet avslutas");
                System.exit(0);
            } catch (SecurityException e) {
                System.out.println("Kontrollera filens läsrättigheter och försök igen.");
                System.out.println();
                System.out.println("Programmet avslutas");
                System.exit(0);
            } catch (InvalidPathException e) {
                System.out.println("Filens sökväg är felaktig.");
                System.out.println();
                System.out.println("Programmet avslutas");
                System.exit(0);
            } catch (IOException e) {
            System.out.println("Något gick fel när filen " + keyFile + " lästes");
            System.out.println("kontrollera att filen existerar och försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
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
            System.out.println("Kryptering avbruten. Programmet avslutas");
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
                    System.out.println("Kryptering avbruten. Programmet avslutas.");
                    System.exit(0);
                }
            }
        }
        DenseMatrix<Rational> theKey = DenseMatrix.valueOf(keyMatrix);
        if((theKey.getNumberOfColumns() < 2) && (theKey.getNumberOfRows() < 2)){
            System.out.println("Nyckeln måste vara en nxn matris med n > 1");
            System.out.println();
            System.out.println("Kryptering avbruten. Programmet avslutas");
            System.exit(0);
        }
        return theKey;
    }

    private DenseMatrix<Rational> getPlainTextMatrix(byte[] plainText, int blockSize) {
        Rational[][] plainMatrix = new Rational[blockSize][plainText.length/blockSize];
        final int COLUMNS = blockSize;
        final int ROWS = plainText.length/blockSize;
        Rational element;
        Rational upperLimit = Rational.valueOf(25,1);
        int offset = 0;
        for (int i = 0; i < ROWS; i++){
            for (int j = 0; j < COLUMNS; j++){
                element = Rational.valueOf(LargeInteger.valueOf(plainText, offset++, 1).minus(65),
                        LargeInteger.ONE);
                plainMatrix[j][i] = element;
                if(element.isNegative() || element.isLargerThan(upperLimit)){
                    System.out.println("Endast tecken A till Z är tillåtna i plaintexten.");
                    System.out.println("Försök igen med tillåtna värden.");
                    System.out.println();
                    System.out.println("Kryptering avbruten. programmet avslutas");
                    System.exit(0);

                }
            }
        }
        return DenseMatrix.valueOf(plainMatrix);
    }

    private byte[] plainTextBlockSequence(int blockSize, String fileName){
        byte[] plainText = null;
        try (FileInputStream fis = new FileInputStream(fileName)){
            final int FILESIZE = (int) fis.getChannel().size();
            if(FILESIZE == 0){
                System.out.println("Filen innehåller ingen data att kryptera.");
                System.out.println();
                System.out.println("Kryptering avbruten. programmet avslutas");
                System.exit(0);
            }
            final int CIPHERSIZE = FILESIZE - (FILESIZE % blockSize);

            plainText = new byte[FILESIZE];
            DataInputStream input  = new DataInputStream(fis);
            for(int i = 0; i < CIPHERSIZE; i++) {
                plainText[i] = input.readByte();
            }
            System.out.println();
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
        System.out.println("SMSCIPHER");
        if(args.length != 5) {
            System.out.println("Fel antal argument.");
            System.out.println("mata in: <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
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
                    if(radix != 26) {
                        System.out.println("Enda tillåtna värde på <radix> = 26");
                        System.out.println("Kryptering avbruten försök igen");
                    } else if(blockSize != 3) {
                        System.out.println("Enda tillåtna värde på <blocksize> = 3");
                        System.out.println("Kryptering avbruten försök igen");
                    } else {
                        new SmsCipher(radix, blockSize, keyFile, plainFile, cipherFile);
                        System.out.println("Kryptering lyckad");
                    }

                } catch (NumberFormatException e) {
                    System.out.println("Enda tillåtna argument är <blocksize> = 3");
                    System.out.println("Programmet anropades med <blocksize> = " + args[1]);
                    System.out.println("Kryptering avbruten försök igen");
                }
            } catch (NumberFormatException e) {
                System.out.println("Enda tillåtna argument är <radix> = 26");
                System.out.println("Programmet anropades med <radix> = " + args[0]);
                System.out.println("Kryptering avbruten försök igen");
            }
        }
        System.out.println("Programmet avslutas");
    }
}
