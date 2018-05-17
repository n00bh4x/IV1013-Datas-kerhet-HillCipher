import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ThreadLocalRandom;
import org.jscience.mathematics.number.LargeInteger;
import org.jscience.mathematics.number.ModuloInteger;
import org.jscience.mathematics.number.Rational;
import org.jscience.mathematics.vector.DenseMatrix;



/**
 * Created by mikaelnorberg on 2017-03-28.
 *
 * Klassen skapar en krypteringsnyckel och en dekrypteringsnyckel och skriver båda till fil.
 */
public class HillKeys {
    private DenseMatrix<Rational> encryptionKey;
    private DenseMatrix<Rational> decryptionKey;
    private final int RADIX;
    private final int DIMENSION;

    /**
     *
     * @param radix modulovärdet
     * @param dimension nycklarnas dimension
     * @param keyFilename krypteringsnyckelfilen
     * @param invKeyFilename dekrypteringsnyckelfilen
     */
    public HillKeys(int radix, int dimension, String keyFilename, String invKeyFilename){
        this.RADIX = radix;
        this.DIMENSION = dimension;
        ModuloInteger.setModulus(LargeInteger.valueOf(RADIX));
        createEncryptionKey();
        createDecryptionKey();
        writeKeyToFile(this.encryptionKey, keyFilename);
        writeKeyToFile(this.decryptionKey, invKeyFilename);
    }


    private void writeKeyToFile(DenseMatrix<Rational> key, String filename) {
        final int ROWS = key.getNumberOfRows();
        final int COLUMNS = key.getNumberOfColumns();
        try (PrintWriter writer = new PrintWriter(filename, "UTF-8")){
            for (int i = 0; i < ROWS; i++) {
                for (int j = 0; j < COLUMNS; j++) {
                    writer.print(key.get(i, j).getDividend());
                    if (j != COLUMNS - 1) {
                        writer.print(" ");
                    }
                }
                if (i != ROWS - 1) {
                    writer.println();
                }
            }
        } catch (FileNotFoundException e) {
            System.out.print("Kontrollera skrivrättigheter för " + filename + " och försök igen.");
            System.out.println();
            System.out.print("Nyckelgenerering avbruten. Programmet avslutas.");
            System.exit(0);
        } catch (IOException e) {
            System.out.println("Något gick fel när data skrevs till " + filename);
            System.out.println("Nyckelgenerering avbruten. Programmet avslutas.");
            System.exit(0);
        }
    }


    private void createDecryptionKey() {
        Rational[][] tempDecryptKey = new Rational[DIMENSION][DIMENSION];
        try {
            Rational inverseDeterminantRest = modInverse(this.encryptionKey);
            this.decryptionKey = this.encryptionKey.inverse().times(inverseDeterminantRest).
                    times(this.encryptionKey.determinant());
            for (int i = 0; i < decryptionKey.getNumberOfRows(); i++) {
                for (int j = 0; j < decryptionKey.getNumberOfRows(); j++) {
                    tempDecryptKey[i][j] = Rational.valueOf(decryptionKey.get(i, j).getDividend().
                            mod(LargeInteger.valueOf(this.RADIX)), LargeInteger.ONE);
                }
            }
            this.decryptionKey = DenseMatrix.valueOf(tempDecryptKey);
        } catch (ArithmeticException e) {
            System.out.println("Något gick fel vid nyckelgenerering. Försök igen.");
            System.out.println("Nyckelgenerering avbruten. Programmet avslutat.");
            System.exit(0);
        }
    }

    public Rational modInverse(DenseMatrix<Rational> key) throws ArithmeticException {
        return Rational.valueOf(key.determinant().
                getDividend().modInverse(ModuloInteger.getModulus()), LargeInteger.ONE);
    }


    private void createEncryptionKey() {
        int randomNumber;
        boolean invertible = false;
        Rational[][] tempKey = new Rational[DIMENSION][DIMENSION];
        while(!invertible) {
            for (int i = 0; i < DIMENSION; i++) {
                for (int j = 0; j < DIMENSION; j++) {
                    randomNumber = ThreadLocalRandom.current().nextInt(0, RADIX);
                    tempKey[i][j] = Rational.valueOf(LargeInteger.valueOf(randomNumber),
                            LargeInteger.ONE);
                }
            }
            try {
                this.encryptionKey = DenseMatrix.valueOf(tempKey);
                if (!this.encryptionKey.determinant().isZero()) {
                    invertible = true;
                    modInverse(this.encryptionKey);
                }
            } catch (ArithmeticException e) {
                invertible = false;
            }
        }
    }



    public static void main(String[] args) {
        System.out.println("HILLKEYS");
        if(args.length != 4) {
            System.out.println("Fel antal argument.");
            System.out.println("mata in: <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
            System.out.println("Försök igen");
        } else {
            int radix;
            int blockSize;
            String keyFile = args[2];
            String invKeyFile = args[3];
            try {
                radix = Integer.parseInt(args[0]);
                try {
                    blockSize = Integer.parseInt(args[1]);
                    if (radix < 2 || radix > 256) {
                        System.out.println("Argumentet <radix> måste uppfylla: 2 <= radix <= 256");
                        System.out.println("Programmet anropades med <radix> = " + args[0]);
                        System.out.println("försök igen");
                    } else if(blockSize < 2 || blockSize > 8) {
                        System.out.println("Argumentet <blocksize> måste uppfylla: 2 <= blocksize <= 8");
                        System.out.println("Programmet anropades med <blocksize> = " + args[1]);
                        System.out.println("försök igen");
                    } else {
                        new HillKeys(radix, blockSize, keyFile, invKeyFile);
                        System.out.println("nyckelgenerering genomförd");
                    }

                } catch (NumberFormatException e) {
                    System.out.println("Endast heltal 2-8 är tillåtna");
                    System.out.println("Programmet anropades med <blocksize> = " + args[1]);
                    System.out.println("försök igen");
                }
            } catch (NumberFormatException e) {
                System.out.println("Endast heltal 2-256 är tillåtna");
                System.out.println("Programmet anropades med <radix> = " + args[0]);
                System.out.println("försök igen");
            }
        }
        System.out.println("Programmet avslutas");
    }
}
