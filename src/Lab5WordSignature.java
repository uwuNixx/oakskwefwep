import java.io.FileOutputStream;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.apache.poi.xwpf.usermodel.XWPFRun;

public class Lab5WordSignature {

    // Задаем русский алфавит
    static final String[] ALPHABET = {
            "А", "Б", "В", "Г", "Д", "Е", "Ё", "Ж", "З", "И", "Й", "К", "Л", "М", "Н", "О", "П", "Р", "С", "Т", "У", "Ф",
            "Х", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Ь", "Э", "Ю", "Я"
    };

    static final long P = 109;
    static final long Q = 1039;
    static final long N = P * Q;
    static final long M = (P - 1) * (Q - 1);

    static long d;
    static long e;

    //Алгоритм Евклида, для поиска НОД
    static long gcd(long a, long b) {
        while (b != 0) {
            long t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    //Проверка простое ли число
    static boolean isPrime(long num) {
        if (num < 2) return false;
        if (num == 2) return true;
        if (num % 2 == 0) return false;
        for (long i = 3; i * i <= num; i += 2) {
            if (num % i == 0) return false;
        }
        return true;
    }

    //Расширенный алгоритм Евклида, для вычисления секретной экспоненты
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

    //Возведение числа в степень по модулю
    static long modPow(long base, long exp, long mod) {
        return java.math.BigInteger.valueOf(base)
                .modPow(java.math.BigInteger.valueOf(exp), java.math.BigInteger.valueOf(mod))
                .longValue();
    }

    //Посимвольная проверка на русскую букву
    static boolean isRussianLetter(char c) {
        return (c >= 'А' && c <= 'Я')
                || (c >= 'а' && c <= 'я')
                || c == 'Ё' || c == 'ё';
    }

    static void generateKeys() {
        //Поиск открытой экспоненты d (простое, взаимно простое с M)
        d = 0;
        for (long candidate = 2; candidate < M; candidate++) {
            if (isPrime(candidate) && gcd(candidate, M) == 1) {
                d = candidate;
                break;
            }
        }
        //Вычисление секретной экспоненты e = d^(-1) mod M
        long[] ext = extendedGcd(d, M);
        e = ext[1] % M;
        if (e < 0) e += M;

        System.out.println("p = " + P);
        System.out.println("q = " + Q);
        System.out.println("n = p * q = " + N);
        System.out.println("m = (p-1)*(q-1) = " + M);
        System.out.println("Открытый ключ  := [d = " + d + ", n = " + N + "]  (ПРОВЕРКА)");
        System.out.println("Секретный ключ := [e = " + e + ", n = " + N + "]  (ПОДПИСЬ)");
        System.out.println();
    }

    //Простая полиномиальная хеш-функция
    static long computeHash(String text) {
        long h = 0;
        for (int i = 0; i < text.length(); i++) {
            h = (h * 31 + text.charAt(i)) % N;
        }
        return h;
    }

    //Создание документа MS Word (.docx)
    static void createDocx(String filename, String text) throws Exception {
        XWPFDocument document = new XWPFDocument();
        XWPFParagraph paragraph = document.createParagraph();
        XWPFRun run = paragraph.createRun();
        run.setText(text);

        FileOutputStream out = new FileOutputStream(filename);
        document.write(out);
        out.close();
        document.close();

        System.out.println("Документ создан: " + filename);
    }

    //Чтение текста из документа MS Word (.docx)
    static String readDocx(String filename) throws Exception {
        XWPFDocument document = new XWPFDocument(java.nio.file.Files.newInputStream(java.nio.file.Paths.get(filename)));
        StringBuilder text = new StringBuilder();
        for (XWPFParagraph paragraph : document.getParagraphs()) {
            text.append(paragraph.getText());
        }
        document.close();
        return text.toString();
    }

    //Меняет одну букву в строке
    static String changeOneLetter(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (isRussianLetter(c)) {
                char upper = Character.toUpperCase(c);
                int idx = -1;
                for (int j = 0; j < ALPHABET.length; j++) {
                    if (ALPHABET[j].charAt(0) == upper) {
                        idx = j;
                        break;
                    }
                }
                if (idx != -1) {
                    char next = ALPHABET[(idx + 1) % ALPHABET.length].charAt(0);
                    if (Character.isLowerCase(c)) next = Character.toLowerCase(next);
                    return s.substring(0, i) + next + s.substring(i + 1);
                }
            }
        }
        return s + "!";
    }

    //ОСНОВНОЙ КЛАСС
    public static void main(String[] args) throws Exception {
        //Генерация ключей
        generateKeys();

        //Создаём исходный документ
        String originalText = "Тестовый документ для проверки цифровой подписи RSA.";
        createDocx("input.docx", originalText);

        //Читаем текст из созданного документа
        String textFromDoc = readDocx("input.docx");
        System.out.println("\nТекст из input.docx: \"" + textFromDoc + "\"");

        //Вычисляем хеш текста
        long hash = computeHash(textFromDoc);
        System.out.println("Хеш текста: " + hash);

        //Подписываем секретным ключом e:
        long signature = modPow(hash, e, N);
        System.out.println("Цифровая подпись (секретным ключом e): " + signature);

        //Проверка 1: документ не изменён
        long verified = modPow(signature, d, N);
        boolean ok = (verified == hash);
        System.out.println("\n--- Проверка 1:");
        System.out.println("Расшифровано открытым ключом d: " + verified);
        System.out.println("Подпись " + (ok ? "ВЕРНА" : "НЕВЕРНА") + " ( хеш совпал )");

        //Проверка 2: изменена одна буква
        String modified1Text = changeOneLetter(textFromDoc);
        createDocx("modified1.docx", modified1Text);
        String text1 = readDocx("modified1.docx");
        long hash1 = computeHash(text1);
        long verified1 = modPow(signature, d, N);
        boolean ok1 = (verified1 == hash1);
        System.out.println("\n--- Проверка 2:");
        System.out.println("Текст: \"" + text1 + "\"");
        System.out.println("Новый хеш: " + hash1);
        System.out.println("Расшифровано открытым ключом d: " + verified1);
        System.out.println("Подпись " + (ok1 ? "ВЕРНА" : "НЕВЕРНА (изменено)"));

        //Проверка 3: добавлена целая строка
        String modified2Text = textFromDoc + " Новая строка для проверки.";
        createDocx("modified2.docx", modified2Text);
        String text2 = readDocx("modified2.docx");
        long hash2 = computeHash(text2);
        long verified2 = modPow(signature, d, N);
        boolean ok2 = (verified2 == hash2);
        System.out.println("\n--- Проверка 3:");
        System.out.println("Текст: \"" + text2 + "\"");
        System.out.println("Новый хеш: " + hash2);
        System.out.println("Расшифровано открытым ключом d: " + verified2);
        System.out.println("Подпись " + (ok2 ? "ВЕРНА" : "НЕВЕРНА (изменено)"));
    }
}