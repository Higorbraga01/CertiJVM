import java.net.HttpURLConnection;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/** Uses the selected Java runtime and its explicitly selected cacerts. */
public final class TlsProbe {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("URL ausente");
            System.exit(2);
        }
        try {
            String password = System.getenv("JVMCERT_STOREPASS");
            if (password != null) {
                System.setProperty("javax.net.ssl.trustStorePassword", password);
            }
            URL url = new URL(args[0]);
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                throw new IllegalArgumentException("Somente HTTPS é aceito");
            }
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(15000);
            connection.setInstanceFollowRedirects(false);
            if (!(connection instanceof HttpsURLConnection)) {
                throw new IllegalArgumentException("A conexão não é HTTPS");
            }
            int status = connection.getResponseCode();
            System.out.println("TLS_OK HTTP_STATUS=" + status);
            connection.disconnect();
        } catch (Exception error) {
            System.err.println(error.getClass().getSimpleName() + ": " + error.getMessage());
            System.exit(1);
        }
    }
}
