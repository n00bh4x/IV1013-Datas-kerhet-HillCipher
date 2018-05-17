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
public class SmsDecipher {

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
    public SmsDecipher(int radix, int blockSize, String keyFile, String plainFile, String cipherFile) {
        byte[] cipherText = cipherTextBlockSequence(cipherFile);
        this.cipherText = getCipherTextMatrix(cipherText, blockSize);
        this.key = getKeyFrom(keyFile);
        this.plainText = decryptCipher(radix);
        writePlainToFile(plainFile);
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
        try {
            DenseVector<Rational> cipherKeyProduct = this.key.times(column);
            final int DIMENSIONS = cipherKeyProduct.getDimension();
            tempVector = new Rational[DIMENSIONS];
            for (int i = 0; i < DIMENSIONS; i++) {
                tempVector[i] = Rational.valueOf(cipherKeyProduct.get(i).getDividend().mod(LargeInteger.valueOf(radix)),
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


    private void writePlainToFile(String plainFile) {
        final int ROWS = this.plainText.getNumberOfRows();
        final int COLUMNS = this.plainText.getNumberOfColumns();
        final int SIZE = COLUMNS * ROWS;
        byte[] plain = new byte[SIZE];
        int index = 0;
        for (int i = 0; i < COLUMNS; i++) {
            for (int j = 0; j < ROWS; j++) {
                if (index >= plain.length) {
                    break;
                } else {
                    plain[index++] = this.plainText.get(j, i).getDividend().plus(65).byteValue();
                }
            }
        }
        try (FileOutputStream fos = new FileOutputStream(plainFile)){
            DataOutputStream output = new DataOutputStream(fos);
            output.write(plain);
            output.close();
        } catch (FileNotFoundException e) {
            System.out.print("Kontrollera skrivrättigheter för " + plainFile + " och försök igen.");
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


    private DenseMatrix<Rational> getCipherTextMatrix(byte[] plainText, int blockSize) {
        Rational[][] plainMatrix = new Rational[blockSize][plainText.length/blockSize];
        final int ROWS = blockSize;
        final int COLUMNS = plainText.length/blockSize;
        Rational element;
        Rational upperLimit = Rational.valueOf(25,1);
        int offset = 0;
        for (int i = 0; i < COLUMNS; i++){
            for (int j = 0; j < ROWS; j++){
                element = Rational.valueOf(LargeInteger.valueOf(plainText, offset++, 1).minus(65),
                        LargeInteger.ONE);
                plainMatrix[j][i] = element;
                if(element.isNegative() || element.isLargerThan(upperLimit)){
                    System.out.println("Varning! Endast tecken A till Z är tillåtna");
                    System.out.println("Information kommer gå förlorad och den dekrypterade ciphertexten");
                    System.out.println("kommer vara skild från plaintexten.");
                    System.out.println("Försök igen med tillåtna värden.");
                    System.out.println();
                    System.out.println("Kryptering avbruten. programmet avslutas");
                    System.exit(0);

                }
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
            plainText = new byte[(int)fis.getChannel().size()];
            DataInputStream input  = new DataInputStream(fis);
            for(int i = 0; i < plainText.length; i++) {
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

        System.out.println("SMSDECIPHER");
        if(args.length != 5) {
            System.out.println("Fel antal argument.");
            System.out.println("mata in: <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
        } else {
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
                        new SmsDecipher(radix, blockSize, keyFile, plainFile, cipherFile);
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

