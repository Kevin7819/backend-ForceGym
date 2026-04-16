package una.force_gym.service;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Service
public class ReCaptchaService {

    @Value("${recaptcha.secret-key}") 
    private String recaptchaSecretKey;

    public boolean verifyRecaptcha(String recaptchaToken) {
        try {
            HttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost("https://www.google.com/recaptcha/api/siteverify");

            // Parámetros 
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("secret", recaptchaSecretKey));
            params.add(new BasicNameValuePair("response", recaptchaToken));

            httpPost.setEntity(new UrlEncodedFormEntity(params));

            HttpResponse response = httpClient.execute(httpPost);

            // Leer respuesta
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent())
            );
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }

            // Verificar si fue exitoso
            return result.toString().contains("\"success\": true");
        } catch (Exception e) {
            return false;
        }
    }
} 
