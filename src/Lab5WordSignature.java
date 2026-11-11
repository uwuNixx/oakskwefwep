import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

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

    // Настройки JWT и простое хранилище пользователей для учебной работы
    static final int TOKEN_LIFETIME_SECONDS = 15 * 60;
    static final int PBKDF2_ITERATIONS = 120_000;
    static final SecureRandom RANDOM = new SecureRandom();
    static final Map<String, String> PASSWORD_HASHES = new HashMap<>();
    static final Map<String, String> PASSWORD_SALTS = new HashMap<>();
    static final String JWT_SECRET = getJwtSecret();

    // Секрет лучше задавать через переменную окружения JWT_SECRET
    static String getJwtSecret() {
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.isEmpty()) {
            return "change-this-demo-secret-please";
        }
        return secret;
    }

    // Алгоритм Евклида, для поиска НОД
    static long gcd(long a, long b) {
        while (b != 0) {
            long t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    // Проверка простое ли число
    static boolean isPrime(long num) {
        if (num < 2) return false;
        if (num == 2) return true;
        if (num % 2 == 0) return false;
        for (long i = 3; i * i <= num; i += 2) {
            if (num % i == 0) return false;
        }
        return true;
    }

    // Расширенный алгоритм Евклида, для вычисления секретной экспоненты
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

    // Возведение числа в степень по модулю
    static long modPow(long base, long exp, long mod) {
        return java.math.BigInteger.valueOf(base)
                .modPow(java.math.BigInteger.valueOf(exp), java.math.BigInteger.valueOf(mod))
                .longValue();
    }

    // Посимвольная проверка на русскую букву
    static boolean isRussianLetter(char c) {
        return (c >= 'А' && c <= 'Я')
                || (c >= 'а' && c <= 'я')
                || c == 'Ё' || c == 'ё';
    }

    // ==================== АВТОРИЗАЦИЯ И JWT ====================

    /**
     * Сначала запускается авторизация, и только после успешной проверки JWT
     * программа переходит к созданию и проверке цифровой подписи документа.
     */
    static String authorize(Scanner scanner) {
        System.out.println("========================================");
        System.out.println(" Авторизация перед подписанием документа");
        System.out.println("========================================");
        System.out.println("Пользователи хранятся только в памяти программы.\n");

        while (true) {
            System.out.println("1 — зарегистрировать пользователя");
            System.out.println("2 — войти и получить JWT");
            System.out.println("0 — выйти");
            System.out.print("Ваш выбор: ");
            String choice = scanner.nextLine().trim();

            if ("1".equals(choice)) {
                registerUser(scanner);
            } else if ("2".equals(choice)) {
                String token = loginUser(scanner);
                if (token != null) {
                    System.out.println("\nJWT-токен:");
                    System.out.println(token);
                    System.out.println("\nТокен состоит из трёх частей:");
                    printTokenParts(token);

                    // Это и есть проверка авторизации перед подписанием.
                    String authorizedUser = verifyToken(token);
                    if (authorizedUser != null) {
                        System.out.println("JWT проверен успешно.");
                        System.out.println("Пользователь " + authorizedUser + " может подписывать документ.\n");
                        return authorizedUser;
                    }

                    System.out.println("JWT не прошёл проверку. Подписание запрещено.\n");
                }
            } else if ("0".equals(choice)) {
                return null;
            } else {
                System.out.println("Неизвестная команда.\n");
            }
        }
    }

    static void registerUser(Scanner scanner) {
        System.out.print("Введите логин (3–32 латинских символа, цифры или _): ");
        String username = scanner.nextLine().trim();

        if (!username.matches("[A-Za-z0-9_]{3,32}")) {
            System.out.println("Некорректный логин.\n");
            return;
        }

        if (PASSWORD_HASHES.containsKey(username)) {
            System.out.println("Такой пользователь уже существует.\n");
            return;
        }

        System.out.print("Введите пароль (минимум 6 символов): ");
        String password = scanner.nextLine();
        if (password.length() < 6) {
            System.out.println("Пароль слишком короткий.\n");
            return;
        }

        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        PASSWORD_SALTS.put(username, base64(salt));
        PASSWORD_HASHES.put(username, base64(hashPassword(password, salt)));
        System.out.println("Пользователь зарегистрирован. Теперь выполните вход.\n");
    }

    static String loginUser(Scanner scanner) {
        System.out.print("Логин: ");
        String username = scanner.nextLine().trim();
        System.out.print("Пароль: ");
        String password = scanner.nextLine();

        String savedHash = PASSWORD_HASHES.get(username);
        String savedSalt = PASSWORD_SALTS.get(username);
        if (savedHash == null || savedSalt == null
                || !verifyPassword(password, savedSalt, savedHash)) {
            System.out.println("Неверный логин или пароль.\n");
            return null;
        }

        return createToken(username);
    }

    static byte[] hashPassword(String password, byte[] salt) {
        try {
            PBEKeySpec specification = new PBEKeySpec(
                    password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
            specification.clearPassword();
            return hash;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Не удалось хешировать пароль", exception);
        }
    }

    static boolean verifyPassword(String password, String encodedSalt, String encodedHash) {
        try {
            byte[] salt = Base64.getDecoder().decode(encodedSalt);
            byte[] expectedHash = Base64.getDecoder().decode(encodedHash);
            byte[] actualHash = hashPassword(password, salt);
            return MessageDigest.isEqual(actualHash, expectedHash);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    /** Создание JWT формата header.payload.signature. */
    static String createToken(String username) {
        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = issuedAt + TOKEN_LIFETIME_SECONDS;

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"" + username
                + "\",\"iat\":" + issuedAt
                + ",\"exp\":" + expiresAt + "}";

        String encodedHeader = base64Url(header.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64Url(payload.getBytes(StandardCharsets.UTF_8));
        String unsignedToken = encodedHeader + "." + encodedPayload;
        return unsignedToken + "." + sign(unsignedToken);
    }

    /** Проверка подписи JWT, пользователя и срока действия токена. */
    static String verifyToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }

        String value = token.trim();
        if (value.startsWith("Bearer ")) {
            value = value.substring("Bearer ".length()).trim();
        }

        String[] parts = value.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty()
                || parts[1].isEmpty() || parts[2].isEmpty()) {
            return null;
        }

        try {
            String header = new String(fromBase64Url(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(fromBase64Url(parts[1]), StandardCharsets.UTF_8);
            if (!"HS256".equals(getStringClaim(header, "alg"))) {
                return null;
            }

            String expectedSignature = sign(parts[0] + "." + parts[1]);
            boolean signatureIsValid = MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.US_ASCII),
                    parts[2].getBytes(StandardCharsets.US_ASCII));
            if (!signatureIsValid) {
                return null;
            }

            String username = getStringClaim(payload, "sub");
            Long expiresAt = getLongClaim(payload, "exp");
            if (username == null || expiresAt == null
                    || expiresAt <= Instant.now().getEpochSecond()) {
                return null;
            }

            // Токен должен относиться к существующему пользователю.
            if (!PASSWORD_HASHES.containsKey(username)) {
                return null;
            }
            return username;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    static String sign(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    JWT_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return base64Url(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Не удалось подписать JWT", exception);
        }
    }

    static void printTokenParts(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return;
        }
        try {
            System.out.println("Header:    "
                    + new String(fromBase64Url(parts[0]), StandardCharsets.UTF_8));
            System.out.println("Payload:   "
                    + new String(fromBase64Url(parts[1]), StandardCharsets.UTF_8));
            System.out.println("Signature: " + parts[2] + "\n");
        } catch (IllegalArgumentException exception) {
            System.out.println("JWT имеет некорректный формат.\n");
        }
    }

    // В этой работе в payload используются только простые строковые и числовые claims.
    static String getStringClaim(String json, String claim) {
        String expression = "\\\"" + Pattern.quote(claim)
                + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"";
        Matcher matcher = Pattern.compile(expression).matcher(json);
        return matcher.find() ? matcher.group(1) : null;
    }

    static Long getLongClaim(String json, String claim) {
        String expression = "\\\"" + Pattern.quote(claim)
                + "\\\"\\s*:\\s*(\\d+)";
        Matcher matcher = Pattern.compile(expression).matcher(json);
        if (!matcher.find()) {
            return null;
        }
        try {
            return Long.parseLong(matcher.group(1));
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    static byte[] fromBase64Url(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    // ==================== ЦИФРОВАЯ ПОДПИСЬ ДОКУМЕНТА ====================

    static void generateKeys() {
        // Поиск открытой экспоненты d (простое, взаимно простое с M)
        d = 0;
        for (long candidate = 2; candidate < M; candidate++) {
            if (isPrime(candidate) && gcd(candidate, M) == 1) {
                d = candidate;
                break;
            }
        }
        // Вычисление секретной экспоненты e = d^(-1) mod M
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

    // Простая полиномиальная хеш-функция
    static long computeHash(String text) {
        long h = 0;
        for (int i = 0; i < text.length(); i++) {
            h = (h * 31 + text.charAt(i)) % N;
        }
        return h;
    }

    // Создание документа MS Word (.docx)
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

    // Чтение текста из документа MS Word (.docx)
    static String readDocx(String filename) throws Exception {
        XWPFDocument document = new XWPFDocument(
                java.nio.file.Files.newInputStream(java.nio.file.Paths.get(filename)));
        StringBuilder text = new StringBuilder();
        for (XWPFParagraph paragraph : document.getParagraphs()) {
            text.append(paragraph.getText());
        }
        document.close();
        return text.toString();
    }

    // Меняет одну букву в строке
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

    // ОСНОВНОЙ КЛАСС
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8.name());

        // Без успешной авторизации до подписания документа дело не дойдёт.
        String authorizedUser = authorize(scanner);
        if (authorizedUser == null) {
            System.out.println("Пользователь не авторизован. Подписание отменено.");
            scanner.close();
            return;
        }

        System.out.println("Подписание запускается от имени пользователя: " + authorizedUser);

        // Генерация ключей и дальнейшая исходная лабораторная работа
        generateKeys();

        // Создаём исходный документ
        String originalText = "Тестовый документ для проверки цифровой подписи RSA.";
        createDocx("input.docx", originalText);

        // Читаем текст из созданного документа
        String textFromDoc = readDocx("input.docx");
        System.out.println("\nТекст из input.docx: \"" + textFromDoc + "\"");

        // Вычисляем хеш текста
        long hash = computeHash(textFromDoc);
        System.out.println("Хеш текста: " + hash);

        // Подписываем секретным ключом e
        long signature = modPow(hash, e, N);
        System.out.println("Цифровая подпись (секретным ключом e): " + signature);

        // Проверка 1: документ не изменён
        long verified = modPow(signature, d, N);
        boolean ok = (verified == hash);
        System.out.println("\n--- Проверка 1:");
        System.out.println("Расшифровано открытым ключом d: " + verified);
        System.out.println("Подпись " + (ok ? "ВЕРНА" : "НЕВЕРНА") + " ( хеш совпал )");

        // Проверка 2: изменена одна буква
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

        // Проверка 3: добавлена целая строка
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
