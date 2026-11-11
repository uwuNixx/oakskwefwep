import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class RSA {
    //
    static final String[] ALPHABET = {
            "А", "Б", "В", "Г", "Д", "Е", "Ё", "Ж", "З", "И", "Й",
            "К", "Л", "М", "Н", "О", "П", "Р", "С", "Т", "У", "Ф",
            "Х", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Ь", "Э", "Ю", "Я"
    };
    //
    static long gcd(long a, long b) {
        while (b != 0) {
            long t = b;
            b = a % b;
            a = t;
        }
        return a;
    }
    //
    static boolean isPrime(long num) {
        if (num < 2) return false;
        if (num == 2) return true;
        if (num % 2 == 0) return false;
        for (long i = 3; i * i <= num; i += 2) {
            if (num % i == 0) return false;
        }
        return true;
    }
    //
    static long[] extendedGcd(long a, long b) {
        if (b == 0) {
            return new long[]{a, 1, 0};
        }
        long[] rec = extendedGcd(b, a % b);
        long g = rec[0];
        long x = rec[2];
        long y = rec[1] - (a / b) * rec[2];
        return new long[]{g, x, y};
    }
    //
    static long modPow(long base, long exp, long mod) {
        return BigInteger.valueOf(base)
                .modPow(BigInteger.valueOf(exp), BigInteger.valueOf(mod))
                .longValue();
    }
    //
    static boolean isRussianWord(String s) {
        if (s == null || s.isEmpty()) return false;
        for (char c : s.toCharArray()) {
            if (!isRussianLetter(c)) return false;
        }
        return true;
    }
    //
    static boolean isRussianLetter(char c) {
        return (c >= 'А' && c <= 'Я')
                || (c >= 'а' && c <= 'я')
                || c == 'Ё' || c == 'ё';
    }
    //
    static int letterToIndex(char c) {
        char upper = Character.toUpperCase(c);
        for (int i = 0; i < ALPHABET.length; i++) {
            if (ALPHABET[i].charAt(0) == upper) {
                return i + 1;
            }
        }
        return -1;
    }
    //
    static String readRussianWord(Scanner scanner) {
        while (true) {
            System.out.print("Введите слово (только русские буквы): ");
            String input = scanner.nextLine().trim();

            if (input.isEmpty()) {
                System.out.println("Ошибка: строка пустая. Попробуйте ещё раз.");
                continue;
            }

            if (!isRussianWord(input)) {
                System.out.println("Ошибка: разрешены только русские буквы (А-Я, а-я, Ё, ё). Попробуйте ещё раз.");
                continue;
            }

            boolean allFound = true;
            for (char c : input.toCharArray()) {
                if (letterToIndex(c) == -1) {
                    System.out.println("Ошибка: буква '" + c + "' отсутствует в алфавите шифрования. Попробуйте ещё раз.");
                    allFound = false;
                    break;
                }
            }
            if (!allFound) continue;

            return input.toUpperCase();
        }
    }
    //
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in, "IBM866");
        //
        long p = 109;
        long q = 1039;
        long n = p * q;
        long m = (p - 1) * (q - 1);

        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("n = " + n);
        System.out.println("m = " + m);
        //
        long d = 0;
        for (long candidate = 2; candidate < m; candidate++) {
            if (isPrime(candidate) && gcd(candidate, m) == 1) {
                d = candidate;
                break;
            }
        }
        System.out.println("PublicKey  := [" + d + ", " + n + "]");
        //
        long[] ext = extendedGcd(d, m);
        long e = ext[1] % m;
        if (e < 0) e += m;
        System.out.println("PrivateKey := [" + e + ", " + n + "]");

        System.out.println();
        //
        String word = readRussianWord(scanner);
        System.out.println("Введённое слово: " + word);
        //
        List<Long> wordDigits = new ArrayList<>();
        for (char c : word.toCharArray()) {
            wordDigits.add((long) letterToIndex(c));
        }
        System.out.println("wordDigits := " + wordDigits);
        //
        List<Long> cipher = new ArrayList<>();
        for (long wd : wordDigits) {
            cipher.add(modPow(wd, d, n));
        }
        System.out.println("cipher     := " + cipher);
        //
        List<Long> decryptedDigits = new ArrayList<>();
        for (long c : cipher) {
            decryptedDigits.add(modPow(c, e, n));
        }
        System.out.println("decrypted  := " + decryptedDigits);
        //
        StringBuilder result = new StringBuilder();
        for (long digit : decryptedDigits) {
            result.append(ALPHABET[(int) (digit - 1)]);
        }
        System.out.println("Результат  : " + result);

        System.out.println("\nНажмите Enter, чтобы выйти...");
        scanner.nextLine();

        scanner.close();
    }
}