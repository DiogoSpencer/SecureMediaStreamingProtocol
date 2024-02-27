package utils;

public class Utils {

    private static final String SEPARATOR = ",";
    private static final int HEXADECIMAL_RADIX = 16;

    /**
     * Takes a csv input with byte values and returns it under the form of a byte array
     * @param input - comma separated hexadecimal values
     * @return byte[] with the represented values
     */
    public static byte[] hexaStringToByteArray(String input){

        String[] bytes = input.split(SEPARATOR);
        byte[] result = new byte[bytes.length];

        int current;
        for (int i = 0; i < bytes.length; i++) {
            current = Integer.parseInt(bytes[i], HEXADECIMAL_RADIX);
            result[i] = (byte) current;
        }



        return result;
    }
}
