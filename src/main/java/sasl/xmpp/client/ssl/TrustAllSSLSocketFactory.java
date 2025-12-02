package sasl.xmpp.client.ssl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jivesoftware.smack.util.SslContextFactory;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustAllSSLSocketFactory implements SslContextFactory {

    private static final Logger log = LogManager.getLogger(TrustAllSSLSocketFactory.class);

    public static HostnameVerifier createHostnameVerifier() {
        log.debug("createHostnameVerifier");
        return new HostnameVerifier() {
            @Override
            public boolean verify(String s, SSLSession sslSession) {
                log.debug("HostnameVerifier#verify");
                return true;
            }
        };
    }

    public static X509TrustManager createTrustManager() {
        log.debug("createTrustManager");
        return new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                log.debug("X509TrustManager#getAcceptedIssuers");
                return new X509Certificate[]{};
            }
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                log.debug("X509TrustManager#checkServerTrusted");
            }
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                log.debug("X509TrustManager#checkClientTrusted");
            }
        };
    }

    @Override
    public SSLContext createSslContext() {
        log.debug("createSslContext");
        TrustManager localTrustManager = createTrustManager();
        log.debug("localTrustManager: {}",  localTrustManager);
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { localTrustManager }, new SecureRandom());
            log.debug("sslContext: {}",  localTrustManager);
            return sslContext;
        } catch (KeyManagementException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }
}