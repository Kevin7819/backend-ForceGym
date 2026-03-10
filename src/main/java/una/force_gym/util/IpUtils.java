package una.force_gym.util;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utilidad para obtener la dirección IP real del cliente
 * considerando proxies y load balancers
 */
public class IpUtils {

    private static final String[] IP_HEADER_CANDIDATES = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
    };

    /**
     * Obtiene la dirección IP real del cliente
     * @param request HttpServletRequest
     * @return Dirección IP del cliente
     */
    public static String getClientIp(HttpServletRequest request) {
        for (String header : IP_HEADER_CANDIDATES) {
            String ipList = request.getHeader(header);
            if (ipList != null && !ipList.isEmpty() && !"unknown".equalsIgnoreCase(ipList)) {
                // En caso de múltiples IPs (proxies encadenados), tomar la primera
                String ip = ipList.split(",")[0].trim();
                if (isValidIp(ip)) {
                    return ip;
                }
            }
        }
        
        // Fallback: usar la IP remota directa
        String remoteAddr = request.getRemoteAddr();
        return remoteAddr != null ? remoteAddr : "0.0.0.0";
    }

    /**
     * Valida si una cadena es una IP válida (formato básico)
     * @param ip Cadena a validar
     * @return true si es una IP válida, false en caso contrario
     */
    private static boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        // Validación básica: no debe ser "unknown" ni vacía
        return !ip.equalsIgnoreCase("unknown") && !ip.trim().isEmpty();
    }
}
