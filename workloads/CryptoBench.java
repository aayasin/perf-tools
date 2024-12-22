// credit: Alexey Ragozin
// source: https://bell-sw.com/announcements/2022/04/07/how-to-use-perf-to-monitor-java-performance/
//
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
public class CryptoBench {
    private static final boolean trackTime = Boolean.getBoolean("trackTime");
    public static void main(String[] args) {
        CryptoBench test = new CryptoBench();
        if (args.length == 0) {
            System.out.println("Error: provide iterations-count");
        } else {
            try {
                int convertedValue = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.out.println("Error - the first argument is not a valid integer");
            }
        }
        int j=0;
        while(j < Integer.parseInt(args[0])) {
            test.execute();
            j++;
        }
    }
    public void execute() {
        long N = 5 * 1000 * 1000;
        RandomStringUtils randomStringUtils = new RandomStringUtils();
        long ts = 0,tf = 0;
        long timer1 = 0;
        long timer2 = 0;
        long bs = System.nanoTime();
        for (long i = 0; i < N; i++) {
                ts = trackTime ? System.nanoTime() : 0;
                String text = randomStringUtils.generate();
                tf = trackTime ? System.nanoTime() : 0;
                timer1 += tf - ts;
                ts = tf;
                crypt(text);
                tf = trackTime ? System.nanoTime() : 0;
                timer2 += tf - ts;
                ts = tf;
        }
        long bt = System.nanoTime() - bs;
        System.out.print(String.format("%.3f Hash-rate-score:Mm/s # %.3f roi-time:seconds",
		0.01 * (N * TimeUnit.SECONDS.toNanos(1) / bt / 10000), bt / 1_000_000_000.0));
        if (trackTime) {
                System.out.print(String.format(" | Generation: %.1f %%",  0.1 * (1000 * timer1 / (timer1 + timer2))));
                System.out.print(String.format(" | Hasing: %.1f %%", 0.1 * (1000 * timer2 / (timer1 + timer2))));
        }
        System.out.println();
        }
        public String crypt(String str) {
        if (str == null || str.length() == 0) {
                throw new IllegalArgumentException("String to encrypt cannot be null or zero length");
        }
        StringBuilder hexString = new StringBuilder();
        try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(str.getBytes());
                byte[] hash = md.digest();
                for (byte aHash : hash) {
                if ((0xff & aHash) < 0x10) {
                        hexString.append("0" + Integer.toHexString((0xFF & aHash)));
                } else {
                        hexString.append(Integer.toHexString(0xFF & aHash));
                }
                }
        } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
        }
        return hexString.toString();
    }
}
class RandomStringUtils {
    public String generate() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 10;
        Random random = new Random();
        StringBuilder buffer = new StringBuilder(targetStringLength);
        for (int i = 0; i < targetStringLength; i++) {
                int randomLimitedInt = leftLimit + (int)
                (random.nextFloat() * (rightLimit - leftLimit + 1));
                buffer.append((char) randomLimitedInt);
        }
        return buffer.toString();
    }
}

