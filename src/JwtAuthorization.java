import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * Простая консольная авторизация с JWT.
 *
 * Внешние библиотеки не нужны: подпись JWT создаётся алгоритмом HMAC-SHA256,
 * а пароль хранится не в открытом виде, а в виде PBKDF2-хеша с солью.
 */
public class JwtAuthorization {

    private static final int TOKEN_LIFETIME_SECONDS = 15 * 60;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int SALT_LENGTH = 16;

    /*
     * Для учебной работы секрет можно оставить таким. В реальном проекте
     * задавайте свой длинный секрет через переменную окружения JWT_SECRET.
     */
    private static final String JWT_SECRET =
            System.getenv().getOrDefault("JWT_SECRET", "change-this-demo-secret-please");

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, String> PASSWORD_HASHES = new HashMap<>();
    private static final Map<String, String> PASSWORD_SALTS = new HashMap<>();

    private static String lastToken = "";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8.name());

        System.out.println("========================================");
        System.out.println(" Авторизация с использованием JWT");
        System.out.println("========================================");
        System.out.println("Пользователи хранятся только в памяти программы.");
        System.out.println("После перезапуска их нужно зарегистрировать заново.\n");

        while (true) {
            printMenu();
            String command = scanner.nextLine().trim();

            try {
                if ("1".equals(command)) {
                    register(scanner);
                } else if ("2".equals(command)) {
                    login(scanner);
                } else if ("3".equals(command)) {
                    openProtectedResource(scanner);
                } else if ("4".equals(command)) {
                    inspectToken(scanner);
                } else if ("0".equals(command)) {
                    System.out.println("Программа завершена.");
                    break;
                } else {
                    System.out.println("Неизвестная команда. Выберите пункт меню.\n");
                }
            } catch (RuntimeException exception) {
                // Не даём одной ошибке закрыть учебную программу.
                System.out.println("Ошибка: " + exception.getMessage() + "\n");
            }
        }

        scanner.close();
    }

    private static void printMenu() {
        System.out.println("Выберите действие:");
        System.out.println("1 — регистрация");
        System.out.println("2 — вход и получение JWT");
        System.out.println("3 — открыть защищённый ресурс");
        System.out.println("4 — разобрать JWT на части");
        System.out.println("0 — выход");
        System.out.print("Ваш выбор: ");
    }

    private static void register(Scanner scanner) {
        System.out.print("Придумайте логин (3–32 латинских символа, цифры или _): ");
        String username = scanner.nextLine().trim();

        if (!username.matches("[A-Za-z0-9_]{3,32}")) {
            System.out.println("Логин введён неверно.\n");
            return;
        }

        if (PASSWORD_HASHES.containsKey(username)) {
            System.out.println("Такой пользователь уже зарегистрирован.\n");
            return;
        }

        System.out.print("Придумайте пароль (минимум 6 символов): ");
        String password = scanner.nextLine();
        if (password.length() < 6) {
            System.out.println("Пароль слишком короткий.\n");
            return;
        }

        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        PASSWORD_SALTS.put(username, base64(salt));
        PASSWORD_HASHES.put(username, hashPassword(password, salt));

        System.out.println("Регистрация завершена. Теперь можно выполнить вход.\n");
    }

    private static void login(Scanner scanner) {
        System.out.print("Логин: ");
        String username = scanner.nextLine().trim();
        System.out.print("Пароль: ");
        String password = scanner.nextLine();

        String savedHash = PASSWORD_HASHES.get(username);
        String savedSalt = PASSWORD_SALTS.get(username);

        if (savedHash == null || savedSalt == null
                || !verifyPassword(password, savedSalt, savedHash)) {
            System.out.println("Неверный логин или пароль.\n");
            return;
        }

        lastToken = createToken(username);
        System.out.println("Вход выполнен успешно.");
        System.out.println("Ваш JWT-токен:");
        System.out.println(lastToken);
        System.out.println("Токен действителен 15 минут и сохранён для пункта 3.\n");
    }

    private static void openProtectedResource(Scanner scanner) {
        String token;

        if (lastToken.isEmpty()) {
            System.out.println("Сначала выполните вход или вставьте JWT-токен.");
            System.out.print("Токен: ");
            token = scanner.nextLine().trim();
        } else {
            System.out.print("JWT-токен (Enter — использовать последний): ");
            String enteredToken = scanner.nextLine().trim();
            token = enteredToken.isEmpty() ? lastToken : enteredToken;
        }

        String username = verifyToken(token);
        if (username == null) {
            System.out.println("Доступ запрещён: токен недействителен или просрочен.\n");
            return;
        }

        System.out.println("Доступ разрешён пользователю " + username + ".");
        System.out.println("Секретные данные защищённого ресурса доступны.\n");
    }

    private static void inspectToken(Scanner scanner) {
        String token = lastToken;
        if (token.isEmpty()) {
            System.out.print("Вставьте JWT-токен: ");
            token = scanner.nextLine().trim();
        }

        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            System.out.println("Это не JWT: должно быть три части через точку.\n");
            return;
        }

        try {
            String header = new String(fromBase64Url(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(fromBase64Url(parts[1]), StandardCharsets.UTF_8);

            System.out.println("Header (алгоритм): " + header);
            System.out.println("Payload (данные):  " + payload);
            System.out.println("Signature (подпись): " + parts[2]);
            System.out.println("Проверка подписи и срока действия:");
            System.out.println(verifyToken(token) == null ? "НЕ ПРОЙДЕНА\n" : "ПРОЙДЕНА\n");
        } catch (IllegalArgumentException exception) {
            System.out.println("JWT содержит некорректный Base64.\n");
        }
    }

    /** Создаёт токен формата header.payload.signature. */
    private static String createToken(String username) {
        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = issuedAt + TOKEN_LIFETIME_SECONDS;

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"" + escapeJson(username)
                + "\",\"iat\":" + issuedAt
                + ",\"exp\":" + expiresAt + "}";

        String encodedHeader = base64Url(header.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64Url(payload.getBytes(StandardCharsets.UTF_8));
        String unsignedToken = encodedHeader + "." + encodedPayload;
        String signature = sign(unsignedToken);

        return unsignedToken + "." + signature;
    }

    /** Проверяет подпись и exp, после чего возвращает логин из claim sub. */
    private static String verifyToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            return null;
        }

        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()
                || parts[2].isEmpty()) {
            return null;
        }

        try {
            String header = new String(fromBase64Url(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(fromBase64Url(parts[1]), StandardCharsets.UTF_8);

            if (!"HS256".equals(jsonString(header, "alg"))) {
                return null;
            }

            String expectedSignature = sign(parts[0] + "." + parts[1]);
            boolean signatureIsValid = MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.US_ASCII),
                    parts[2].getBytes(StandardCharsets.US_ASCII));
            if (!signatureIsValid) {
                return null;
            }

            String username = jsonString(payload, "sub");
            Long expiresAt = jsonLong(payload, "exp");
            if (username == null || expiresAt == null || expiresAt < Instant.now().getEpochSecond()) {
                return null;
            }

            return username;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static String sign(String value) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec key = new javax.crypto.spec.SecretKeySpec(
                    JWT_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(key);
            return base64Url(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Не удалось создать подпись JWT", exception);
        }
    }

    private static String hashPassword(String password, byte[] salt) {
        try {
            PBEKeySpec specification = new PBEKeySpec(
                    password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
            specification.clearPassword();
            return base64(hash);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Не удалось хешировать пароль", exception);
        }
    }

    private static boolean verifyPassword(String password, String encodedSalt, String savedHash) {
        try {
            byte[] salt = Base64.getDecoder().decode(encodedSalt);
            byte[] actualHash = Base64.getDecoder().decode(savedHash);
            byte[] expectedHash = Base64.getDecoder().decode(hashPassword(password, salt));
            return MessageDigest.isEqual(actualHash, expectedHash);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] fromBase64Url(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    private static String escapeJson(String value) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            if (character == '"') {
                result.append("\\\"");
            } else if (character == '\\') {
                result.append("\\\\");
            } else if (character == '\n') {
                result.append("\\n");
            } else if (character == '\r') {
                result.append("\\r");
            } else if (character == '\t') {
                result.append("\\t");
            } else if (character < 32) {
                result.append(String.format("\\u%04x", (int) character));
            } else {
                result.append(character);
            }
        }
        return result.toString();
    }

    /* Небольшой разбор JSON: для JWT достаточно строковых и числовых claim. */
    private static String jsonString(String json, String key) {
        int valueStart = jsonValueStart(json, key);
        if (valueStart < 0 || valueStart >= json.length() || json.charAt(valueStart) != '"') {
            return null;
        }

        StringBuilder result = new StringBuilder();
        for (int i = valueStart + 1; i < json.length(); i++) {
            char character = json.charAt(i);
            if (character == '"') {
                return result.toString();
            }
            if (character != '\\') {
                result.append(character);
                continue;
            }

            if (++i >= json.length()) {
                return null;
            }
            character = json.charAt(i);
            if (character == '"' || character == '\\' || character == '/') {
                result.append(character);
            } else if (character == 'b') {
                result.append('\b');
            } else if (character == 'f') {
                result.append('\f');
            } else if (character == 'n') {
                result.append('\n');
            } else if (character == 'r') {
                result.append('\r');
            } else if (character == 't') {
                result.append('\t');
            } else if (character == 'u' && i + 4 < json.length()) {
                try {
                    result.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                    i += 4;
                } catch (NumberFormatException exception) {
                    return null;
                }
            } else {
                return null;
            }
        }
        return null;
    }

    private static Long jsonLong(String json, String key) {
        int valueStart = jsonValueStart(json, key);
        if (valueStart < 0) {
            return null;
        }

        int valueEnd = valueStart;
        while (valueEnd < json.length()
                && (json.charAt(valueEnd) == '-' || Character.isDigit(json.charAt(valueEnd)))) {
            valueEnd++;
        }
        if (valueEnd == valueStart) {
            return null;
        }

        try {
            return Long.parseLong(json.substring(valueStart, valueEnd));
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static int jsonValueStart(String json, String key) {
        String marker = "\"" + key + "\"";
        int keyStart = json.indexOf(marker);
        if (keyStart < 0) {
            return -1;
        }

        int colon = json.indexOf(':', keyStart + marker.length());
        if (colon < 0) {
            return -1;
        }

        int valueStart = colon + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }
        return valueStart;
    }
}
